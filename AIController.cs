using Azure;
using Azure.Search.Documents;
using Azure.Search.Documents.Models;
using Azure.AI.OpenAI;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Concurrent;
using Microsoft.AspNetCore.Authorization;
using System.Text.RegularExpressions;

namespace AzureAIAssistant.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class AIController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<AIController> _logger;
        private static ConcurrentDictionary<string, ChatSession> _sessions = new();
        private const int MAX_HISTORY_LENGTH = 10;
        private const double MIN_SEARCH_SCORE = 0.7;

        public AIController(ILogger<AIController> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        public class ChatSession
        {
            public string UserId { get; set; }
            public string UserEmail { get; set; }
            public List<ChatMessage> History { get; set; } = new();
            public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
            public DateTime LastActivityAt { get; set; } = DateTime.UtcNow;
        }

        public class AskRequest
        {
            public string? UserQuestion { get; set; }
            public string? SessionId { get; set; }
        }

        public class AskResponse
        {
            public string? Answer { get; set; }
            public List<MessageDTO>? History { get; set; }
        }

        public class MessageDTO
        {
            public string Role { get; set; } = string.Empty;
            public string Content { get; set; } = string.Empty;
        }

        public class SearchRequest
        {
            public string? Query { get; set; }
        }

        public class SearchResultItem
        {
            public string Content { get; set; }
            public double Score { get; set; }
        }

        public class SearchResultResponse
        {
            public List<SearchResultItem> Results { get; set; } = new List<SearchResultItem>();
            public string ProcessedQuery { get; set; }
            public int TotalCount { get; set; }
        }

        [HttpPost("ask")]
        public async Task<IActionResult> Ask([FromBody] AskRequest request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request.UserQuestion) || string.IsNullOrWhiteSpace(request.SessionId))
                {
                    return BadRequest(new { Answer = "Please enter a question and session ID." });
                }

                _logger.LogInformation($"Processing question: {request.UserQuestion} for session: {request.SessionId}");

                var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
                var userEmail = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value;
                
                if (string.IsNullOrEmpty(userId))
                {
                    return Unauthorized(new { Answer = "Authentication required." });
                }

                var session = _sessions.GetOrAdd(request.SessionId, new ChatSession 
                { 
                    UserId = userId,
                    UserEmail = userEmail ?? "Unknown",
                    History = new List<ChatMessage>(),
                    CreatedAt = DateTime.UtcNow
                });
                
                session.LastActivityAt = DateTime.UtcNow;
                
                if (session.UserId != userId && !User.IsInRole("admin"))
                {
                    return Forbid();
                }

                string processedQuery = PreprocessQuery(request.UserQuestion);
                var searchResults = await GetSearchResultsAsync(processedQuery);
                
                string answer;
                if (searchResults.Count > 0)
                {
                    string context = string.Join("\n\n", searchResults);
                    string systemPrompt = $"You are a helpful assistant that answers questions using the provided content. " +
                                      $"Base your answers on this context:\n\n{context}\n\n" +
                                      "If you don't know the answer based on the provided context, say clearly that you don't have enough information to answer the question accurately. " +
                                      "Never make up information or hallucinate facts not present in the context. " +
                                      "Format your responses using markdown for better readability. " +
                                      "Use proper markdown syntax for headings, lists, code blocks, and emphasis.";

                    var systemMessage = new ChatMessage(ChatRole.System, systemPrompt);
                    var messages = new List<ChatMessage> { systemMessage };
                    
                    messages.AddRange(session.History.TakeLast(MAX_HISTORY_LENGTH));
                    
                    var userMessage = new ChatMessage(ChatRole.User, request.UserQuestion);
                    messages.Add(userMessage);
                    
                    answer = await GetAnswerFromOpenAIAsync(messages);
                    
                    var assistantMessage = new ChatMessage(ChatRole.Assistant, answer);
                    session.History.Add(userMessage);
                    session.History.Add(assistantMessage);
                }
                else
                {
                    answer = "I don't have enough information to answer that question accurately. Could you please rephrase or ask about something else?";
                    
                    var userMessage = new ChatMessage(ChatRole.User, request.UserQuestion);
                    var assistantMessage = new ChatMessage(ChatRole.Assistant, answer);
                    session.History.Add(userMessage);
                    session.History.Add(assistantMessage);
                }
                
                var historyDTO = session.History.Select(m => new MessageDTO 
                { 
                    Role = m.Role.ToString().ToLower(),
                    Content = m.Content
                }).ToList();

                var response = new AskResponse 
                { 
                    Answer = answer, 
                    History = historyDTO
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing request");
                return StatusCode(500, new { Answer = $"An error occurred: {ex.Message}" });
            }
        }

        [HttpGet("history/{sessionId}")]
        public IActionResult GetHistory(string sessionId)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(sessionId) || !_sessions.ContainsKey(sessionId))
                {
                    _logger.LogWarning($"No history found for session: {sessionId}");
                    return NotFound(new { Message = "No history found for this session." });
                }

                var session = _sessions[sessionId];
                var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
                
                if (session.UserId != userId && !User.IsInRole("admin"))
                {
                    return Forbid();
                }

                var historyDTO = session.History.Select(m => new MessageDTO 
                { 
                    Role = m.Role.ToString().ToLower(), 
                    Content = m.Content 
                }).ToList();

                _logger.LogInformation($"Retrieved history for session {sessionId}: {session.History.Count} messages");
                return Ok(historyDTO);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving history");
                return StatusCode(500, new { Message = $"An error occurred: {ex.Message}" });
            }
        }

        [HttpPost("clear-history/{sessionId}")]
        public IActionResult ClearHistory(string sessionId)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(sessionId))
                {
                    return BadRequest(new { Message = "Session ID is required." });
                }

                if (!_sessions.TryGetValue(sessionId, out var session))
                {
                    return NotFound(new { Message = "Session not found." });
                }
                
                var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
                
                if (session.UserId != userId && !User.IsInRole("admin"))
                {
                    return Forbid();
                }

                bool removed = _sessions.TryRemove(sessionId, out _);
                _logger.LogInformation($"Cleared history for session {sessionId}: {(removed ? "successful" : "not found")}");
                
                return Ok(new { Message = "Session history cleared successfully." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error clearing history");
                return StatusCode(500, new { Message = $"An error occurred: {ex.Message}" });
            }
        }
        
        [HttpPost("admin/search")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> AdminSearch([FromBody] SearchRequest request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request.Query))
                {
                    return BadRequest(new { Message = "Search query is required." });
                }

                string processedQuery = PreprocessQuery(request.Query);
                var searchResults = await GetRawSearchResultsAsync(processedQuery);
                
                return Ok(searchResults);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error performing admin search");
                return StatusCode(500, new { Message = $"An error occurred: {ex.Message}" });
            }
        }

        private string PreprocessQuery(string query)
        {
            if (string.IsNullOrWhiteSpace(query))
                return query;
                
            try
            {
                var stopWords = new[] { "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "with", "by" };
                
                query = query.ToLowerInvariant();
                
                var words = query.Split(new[] { ' ', ',', '.', '?', '!', ';', ':', '-', '(', ')', '[', ']', '{', '}' }, 
                    StringSplitOptions.RemoveEmptyEntries);
                
                var filteredWords = words.Where(w => !stopWords.Contains(w)).ToList();
                
                if (filteredWords.Count == 0)
                    return query;
                    
                return string.Join(" ", filteredWords);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error preprocessing query");
                return query;
            }
        }

        private async Task<List<string>> GetSearchResultsAsync(string query)
        {
            _logger.LogInformation($"Searching in Azure Cognitive Search for: '{query}'");
            
            try
            {
                string searchServiceEndpoint = _configuration["AzureSearch:Endpoint"];
                string indexName = _configuration["AzureSearch:IndexName"];
                string searchApiKey = _configuration["AzureSearch:ApiKey"];

                var credential = new AzureKeyCredential(searchApiKey);
                var client = new SearchClient(new Uri(searchServiceEndpoint), indexName, credential);

                var options = new SearchOptions
                {
                    Size = 3,
                    QueryType = SearchQueryType.Full,
                    IncludeTotalCount = true
                };
                
                options.Select.Add("chunk");

                var response = await client.SearchAsync<SearchDocument>(query, options);
                
                var results = new List<string>();
                _logger.LogInformation($"Search returned {response.Value.TotalCount} total results");

                var queryTerms = query.ToLowerInvariant().Split(new[] { ' ', ',', '.', '?', '!', ';', ':', '-', '(', ')', '[', ']', '{', '}' }, 
                    StringSplitOptions.RemoveEmptyEntries)
                    .Where(term => term.Length > 2)
                    .ToList();

                await foreach (var result in response.Value.GetResultsAsync())
                {
                    var score = result.Score;
                    if (score < MIN_SEARCH_SCORE)
                    {
                        continue;
                    }
                    
                    if (result.Document.TryGetValue("chunk", out var content) && content != null)
                    {
                        string contentStr = content.ToString();
                        bool containsQueryTerms = queryTerms.Any(term => 
                            contentStr.ToLowerInvariant().Contains(term));
                            
                        if (!string.IsNullOrWhiteSpace(contentStr) && contentStr.Length > 10 && containsQueryTerms)
                        {
                            results.Add(contentStr);
                        }
                    }
                }

                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error performing search");
                return new List<string>();
            }
        }

        private async Task<SearchResultResponse> GetRawSearchResultsAsync(string query)
        {
            _logger.LogInformation($"Admin searching in Azure Cognitive Search for: '{query}'");
            
            try
            {
                string searchServiceEndpoint = _configuration["AzureSearch:Endpoint"];
                string indexName = _configuration["AzureSearch:IndexName"];
                string searchApiKey = _configuration["AzureSearch:ApiKey"];

                var credential = new AzureKeyCredential(searchApiKey);
                var client = new SearchClient(new Uri(searchServiceEndpoint), indexName, credential);

                var options = new SearchOptions
                {
                    Size = 10,
                    QueryType = SearchQueryType.Full,
                    IncludeTotalCount = true
                };
                
                options.Select.Add("chunk");

                var response = await client.SearchAsync<SearchDocument>(query, options);
                
                var results = new List<SearchResultItem>();
                long totalCount = response.Value.TotalCount ?? 0;

                await foreach (var result in response.Value.GetResultsAsync())
                {
                    if (result.Document.TryGetValue("chunk", out var content) && content != null)
                    {
                        string contentStr = content.ToString();
                        if (!string.IsNullOrWhiteSpace(contentStr) && contentStr.Length > 10)
                        {
                            results.Add(new SearchResultItem 
                            { 
                                Content = contentStr,
                                Score = result.Score ?? 0
                            });
                        }
                    }
                }

                return new SearchResultResponse
                {
                    Results = results,
                    ProcessedQuery = query,
                    TotalCount = (int)totalCount
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error performing admin search");
                throw;
            }
        }

        private string EnhanceMarkdownResponse(string response)
        {
            try
            {
                var codeBlockPattern = @"```(\w*)\s*([\s\S]*?)```";
                response = Regex.Replace(response, codeBlockPattern, match =>
                {
                    string language = match.Groups[1].Value.Trim();
                    string code = match.Groups[2].Value.Trim();
                    
                    return $"```{language}\n{code}\n```";
                });
                
                return response;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error enhancing markdown");
                return response;
            }
        }

        private async Task<string> GetAnswerFromOpenAIAsync(List<ChatMessage> messages)
        {
            _logger.LogInformation($"Sending request to OpenAI with {messages.Count} messages");
            
            try
            {
                string openAiEndpoint = _configuration["OpenAI:Endpoint"];
                string openAiApiKey = _configuration["OpenAI:ApiKey"];
                string deploymentName = _configuration["OpenAI:DeploymentName"];

                var client = new OpenAIClient(new Uri(openAiEndpoint), new AzureKeyCredential(openAiApiKey));

                var chatOptions = new ChatCompletionsOptions
                {
                    Temperature = 0.1f,
                    MaxTokens = 500
                };
                
                foreach (var message in messages)
                {
                    chatOptions.Messages.Add(message);
                }

                var response = await client.GetChatCompletionsAsync(deploymentName, chatOptions);
                var content = response.Value.Choices[0].Message.Content.Trim();
                
                return EnhanceMarkdownResponse(content);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting answer from OpenAI");
                return "I'm sorry, but I encountered an issue processing your request. Please try again later.";
            }
        }
    }
}