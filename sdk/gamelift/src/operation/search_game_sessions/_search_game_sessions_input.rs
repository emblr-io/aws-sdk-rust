// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SearchGameSessionsInput {
    /// <p>A unique identifier for the fleet to search for active game sessions. You can use either the fleet ID or ARN value. Each request must reference either a fleet ID or alias ID, but not both.</p>
    pub fleet_id: ::std::option::Option<::std::string::String>,
    /// <p>A unique identifier for the alias associated with the fleet to search for active game sessions. You can use either the alias ID or ARN value. Each request must reference either a fleet ID or alias ID, but not both.</p>
    pub alias_id: ::std::option::Option<::std::string::String>,
    /// <p>A fleet location to search for game sessions. You can specify a fleet's home Region or a remote location. Use the Amazon Web Services Region code format, such as <code>us-west-2</code>.</p>
    pub location: ::std::option::Option<::std::string::String>,
    /// <p>String containing the search criteria for the session search. If no filter expression is included, the request returns results for all game sessions in the fleet that are in <code>ACTIVE</code> status.</p>
    /// <p>A filter expression can contain one or multiple conditions. Each condition consists of the following:</p>
    /// <ul>
    /// <li>
    /// <p><b>Operand</b> -- Name of a game session attribute. Valid values are <code>gameSessionName</code>, <code>gameSessionId</code>, <code>gameSessionProperties</code>, <code>maximumSessions</code>, <code>creationTimeMillis</code>, <code>playerSessionCount</code>, <code>hasAvailablePlayerSessions</code>.</p></li>
    /// <li>
    /// <p><b>Comparator</b> -- Valid comparators are: <code>=</code>, <code>&lt;&gt;</code>, <code>&lt;</code>, <code>&gt;</code>, <code>&lt;=</code>, <code>&gt;=</code>.</p></li>
    /// <li>
    /// <p><b>Value</b> -- Value to be searched for. Values may be numbers, boolean values (true/false) or strings depending on the operand. String values are case sensitive and must be enclosed in single quotes. Special characters must be escaped. Boolean and string values can only be used with the comparators <code>=</code> and <code>&lt;&gt;</code>. For example, the following filter expression searches on <code>gameSessionName</code>: "<code>FilterExpression": "gameSessionName = 'Matt\\'s Awesome Game 1'"</code>.</p></li>
    /// </ul>
    /// <p>To chain multiple conditions in a single expression, use the logical keywords <code>AND</code>, <code>OR</code>, and <code>NOT</code> and parentheses as needed. For example: <code>x AND y AND NOT z</code>, <code>NOT (x OR y)</code>.</p>
    /// <p>Session search evaluates conditions from left to right using the following precedence rules:</p>
    /// <ol>
    /// <li>
    /// <p><code>=</code>, <code>&lt;&gt;</code>, <code>&lt;</code>, <code>&gt;</code>, <code>&lt;=</code>, <code>&gt;=</code></p></li>
    /// <li>
    /// <p>Parentheses</p></li>
    /// <li>
    /// <p>NOT</p></li>
    /// <li>
    /// <p>AND</p></li>
    /// <li>
    /// <p>OR</p></li>
    /// </ol>
    /// <p>For example, this filter expression retrieves game sessions hosting at least ten players that have an open player slot: <code>"maximumSessions&gt;=10 AND hasAvailablePlayerSessions=true"</code>.</p>
    pub filter_expression: ::std::option::Option<::std::string::String>,
    /// <p>Instructions on how to sort the search results. If no sort expression is included, the request returns results in random order. A sort expression consists of the following elements:</p>
    /// <ul>
    /// <li>
    /// <p><b>Operand</b> -- Name of a game session attribute. Valid values are <code>gameSessionName</code>, <code>gameSessionId</code>, <code>gameSessionProperties</code>, <code>maximumSessions</code>, <code>creationTimeMillis</code>, <code>playerSessionCount</code>, <code>hasAvailablePlayerSessions</code>.</p></li>
    /// <li>
    /// <p><b>Order</b> -- Valid sort orders are <code>ASC</code> (ascending) and <code>DESC</code> (descending).</p></li>
    /// </ul>
    /// <p>For example, this sort expression returns the oldest active sessions first: <code>"SortExpression": "creationTimeMillis ASC"</code>. Results with a null value for the sort operand are returned at the end of the list.</p>
    pub sort_expression: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages. The maximum number of results returned is 20, even if this value is not set or is set higher than 20.</p>
    pub limit: ::std::option::Option<i32>,
    /// <p>A token that indicates the start of the next sequential page of results. Use the token that is returned with a previous call to this operation. To start at the beginning of the result set, do not specify a value.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl SearchGameSessionsInput {
    /// <p>A unique identifier for the fleet to search for active game sessions. You can use either the fleet ID or ARN value. Each request must reference either a fleet ID or alias ID, but not both.</p>
    pub fn fleet_id(&self) -> ::std::option::Option<&str> {
        self.fleet_id.as_deref()
    }
    /// <p>A unique identifier for the alias associated with the fleet to search for active game sessions. You can use either the alias ID or ARN value. Each request must reference either a fleet ID or alias ID, but not both.</p>
    pub fn alias_id(&self) -> ::std::option::Option<&str> {
        self.alias_id.as_deref()
    }
    /// <p>A fleet location to search for game sessions. You can specify a fleet's home Region or a remote location. Use the Amazon Web Services Region code format, such as <code>us-west-2</code>.</p>
    pub fn location(&self) -> ::std::option::Option<&str> {
        self.location.as_deref()
    }
    /// <p>String containing the search criteria for the session search. If no filter expression is included, the request returns results for all game sessions in the fleet that are in <code>ACTIVE</code> status.</p>
    /// <p>A filter expression can contain one or multiple conditions. Each condition consists of the following:</p>
    /// <ul>
    /// <li>
    /// <p><b>Operand</b> -- Name of a game session attribute. Valid values are <code>gameSessionName</code>, <code>gameSessionId</code>, <code>gameSessionProperties</code>, <code>maximumSessions</code>, <code>creationTimeMillis</code>, <code>playerSessionCount</code>, <code>hasAvailablePlayerSessions</code>.</p></li>
    /// <li>
    /// <p><b>Comparator</b> -- Valid comparators are: <code>=</code>, <code>&lt;&gt;</code>, <code>&lt;</code>, <code>&gt;</code>, <code>&lt;=</code>, <code>&gt;=</code>.</p></li>
    /// <li>
    /// <p><b>Value</b> -- Value to be searched for. Values may be numbers, boolean values (true/false) or strings depending on the operand. String values are case sensitive and must be enclosed in single quotes. Special characters must be escaped. Boolean and string values can only be used with the comparators <code>=</code> and <code>&lt;&gt;</code>. For example, the following filter expression searches on <code>gameSessionName</code>: "<code>FilterExpression": "gameSessionName = 'Matt\\'s Awesome Game 1'"</code>.</p></li>
    /// </ul>
    /// <p>To chain multiple conditions in a single expression, use the logical keywords <code>AND</code>, <code>OR</code>, and <code>NOT</code> and parentheses as needed. For example: <code>x AND y AND NOT z</code>, <code>NOT (x OR y)</code>.</p>
    /// <p>Session search evaluates conditions from left to right using the following precedence rules:</p>
    /// <ol>
    /// <li>
    /// <p><code>=</code>, <code>&lt;&gt;</code>, <code>&lt;</code>, <code>&gt;</code>, <code>&lt;=</code>, <code>&gt;=</code></p></li>
    /// <li>
    /// <p>Parentheses</p></li>
    /// <li>
    /// <p>NOT</p></li>
    /// <li>
    /// <p>AND</p></li>
    /// <li>
    /// <p>OR</p></li>
    /// </ol>
    /// <p>For example, this filter expression retrieves game sessions hosting at least ten players that have an open player slot: <code>"maximumSessions&gt;=10 AND hasAvailablePlayerSessions=true"</code>.</p>
    pub fn filter_expression(&self) -> ::std::option::Option<&str> {
        self.filter_expression.as_deref()
    }
    /// <p>Instructions on how to sort the search results. If no sort expression is included, the request returns results in random order. A sort expression consists of the following elements:</p>
    /// <ul>
    /// <li>
    /// <p><b>Operand</b> -- Name of a game session attribute. Valid values are <code>gameSessionName</code>, <code>gameSessionId</code>, <code>gameSessionProperties</code>, <code>maximumSessions</code>, <code>creationTimeMillis</code>, <code>playerSessionCount</code>, <code>hasAvailablePlayerSessions</code>.</p></li>
    /// <li>
    /// <p><b>Order</b> -- Valid sort orders are <code>ASC</code> (ascending) and <code>DESC</code> (descending).</p></li>
    /// </ul>
    /// <p>For example, this sort expression returns the oldest active sessions first: <code>"SortExpression": "creationTimeMillis ASC"</code>. Results with a null value for the sort operand are returned at the end of the list.</p>
    pub fn sort_expression(&self) -> ::std::option::Option<&str> {
        self.sort_expression.as_deref()
    }
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages. The maximum number of results returned is 20, even if this value is not set or is set higher than 20.</p>
    pub fn limit(&self) -> ::std::option::Option<i32> {
        self.limit
    }
    /// <p>A token that indicates the start of the next sequential page of results. Use the token that is returned with a previous call to this operation. To start at the beginning of the result set, do not specify a value.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl SearchGameSessionsInput {
    /// Creates a new builder-style object to manufacture [`SearchGameSessionsInput`](crate::operation::search_game_sessions::SearchGameSessionsInput).
    pub fn builder() -> crate::operation::search_game_sessions::builders::SearchGameSessionsInputBuilder {
        crate::operation::search_game_sessions::builders::SearchGameSessionsInputBuilder::default()
    }
}

/// A builder for [`SearchGameSessionsInput`](crate::operation::search_game_sessions::SearchGameSessionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SearchGameSessionsInputBuilder {
    pub(crate) fleet_id: ::std::option::Option<::std::string::String>,
    pub(crate) alias_id: ::std::option::Option<::std::string::String>,
    pub(crate) location: ::std::option::Option<::std::string::String>,
    pub(crate) filter_expression: ::std::option::Option<::std::string::String>,
    pub(crate) sort_expression: ::std::option::Option<::std::string::String>,
    pub(crate) limit: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl SearchGameSessionsInputBuilder {
    /// <p>A unique identifier for the fleet to search for active game sessions. You can use either the fleet ID or ARN value. Each request must reference either a fleet ID or alias ID, but not both.</p>
    pub fn fleet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.fleet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the fleet to search for active game sessions. You can use either the fleet ID or ARN value. Each request must reference either a fleet ID or alias ID, but not both.</p>
    pub fn set_fleet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.fleet_id = input;
        self
    }
    /// <p>A unique identifier for the fleet to search for active game sessions. You can use either the fleet ID or ARN value. Each request must reference either a fleet ID or alias ID, but not both.</p>
    pub fn get_fleet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.fleet_id
    }
    /// <p>A unique identifier for the alias associated with the fleet to search for active game sessions. You can use either the alias ID or ARN value. Each request must reference either a fleet ID or alias ID, but not both.</p>
    pub fn alias_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.alias_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the alias associated with the fleet to search for active game sessions. You can use either the alias ID or ARN value. Each request must reference either a fleet ID or alias ID, but not both.</p>
    pub fn set_alias_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.alias_id = input;
        self
    }
    /// <p>A unique identifier for the alias associated with the fleet to search for active game sessions. You can use either the alias ID or ARN value. Each request must reference either a fleet ID or alias ID, but not both.</p>
    pub fn get_alias_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.alias_id
    }
    /// <p>A fleet location to search for game sessions. You can specify a fleet's home Region or a remote location. Use the Amazon Web Services Region code format, such as <code>us-west-2</code>.</p>
    pub fn location(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.location = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A fleet location to search for game sessions. You can specify a fleet's home Region or a remote location. Use the Amazon Web Services Region code format, such as <code>us-west-2</code>.</p>
    pub fn set_location(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.location = input;
        self
    }
    /// <p>A fleet location to search for game sessions. You can specify a fleet's home Region or a remote location. Use the Amazon Web Services Region code format, such as <code>us-west-2</code>.</p>
    pub fn get_location(&self) -> &::std::option::Option<::std::string::String> {
        &self.location
    }
    /// <p>String containing the search criteria for the session search. If no filter expression is included, the request returns results for all game sessions in the fleet that are in <code>ACTIVE</code> status.</p>
    /// <p>A filter expression can contain one or multiple conditions. Each condition consists of the following:</p>
    /// <ul>
    /// <li>
    /// <p><b>Operand</b> -- Name of a game session attribute. Valid values are <code>gameSessionName</code>, <code>gameSessionId</code>, <code>gameSessionProperties</code>, <code>maximumSessions</code>, <code>creationTimeMillis</code>, <code>playerSessionCount</code>, <code>hasAvailablePlayerSessions</code>.</p></li>
    /// <li>
    /// <p><b>Comparator</b> -- Valid comparators are: <code>=</code>, <code>&lt;&gt;</code>, <code>&lt;</code>, <code>&gt;</code>, <code>&lt;=</code>, <code>&gt;=</code>.</p></li>
    /// <li>
    /// <p><b>Value</b> -- Value to be searched for. Values may be numbers, boolean values (true/false) or strings depending on the operand. String values are case sensitive and must be enclosed in single quotes. Special characters must be escaped. Boolean and string values can only be used with the comparators <code>=</code> and <code>&lt;&gt;</code>. For example, the following filter expression searches on <code>gameSessionName</code>: "<code>FilterExpression": "gameSessionName = 'Matt\\'s Awesome Game 1'"</code>.</p></li>
    /// </ul>
    /// <p>To chain multiple conditions in a single expression, use the logical keywords <code>AND</code>, <code>OR</code>, and <code>NOT</code> and parentheses as needed. For example: <code>x AND y AND NOT z</code>, <code>NOT (x OR y)</code>.</p>
    /// <p>Session search evaluates conditions from left to right using the following precedence rules:</p>
    /// <ol>
    /// <li>
    /// <p><code>=</code>, <code>&lt;&gt;</code>, <code>&lt;</code>, <code>&gt;</code>, <code>&lt;=</code>, <code>&gt;=</code></p></li>
    /// <li>
    /// <p>Parentheses</p></li>
    /// <li>
    /// <p>NOT</p></li>
    /// <li>
    /// <p>AND</p></li>
    /// <li>
    /// <p>OR</p></li>
    /// </ol>
    /// <p>For example, this filter expression retrieves game sessions hosting at least ten players that have an open player slot: <code>"maximumSessions&gt;=10 AND hasAvailablePlayerSessions=true"</code>.</p>
    pub fn filter_expression(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.filter_expression = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>String containing the search criteria for the session search. If no filter expression is included, the request returns results for all game sessions in the fleet that are in <code>ACTIVE</code> status.</p>
    /// <p>A filter expression can contain one or multiple conditions. Each condition consists of the following:</p>
    /// <ul>
    /// <li>
    /// <p><b>Operand</b> -- Name of a game session attribute. Valid values are <code>gameSessionName</code>, <code>gameSessionId</code>, <code>gameSessionProperties</code>, <code>maximumSessions</code>, <code>creationTimeMillis</code>, <code>playerSessionCount</code>, <code>hasAvailablePlayerSessions</code>.</p></li>
    /// <li>
    /// <p><b>Comparator</b> -- Valid comparators are: <code>=</code>, <code>&lt;&gt;</code>, <code>&lt;</code>, <code>&gt;</code>, <code>&lt;=</code>, <code>&gt;=</code>.</p></li>
    /// <li>
    /// <p><b>Value</b> -- Value to be searched for. Values may be numbers, boolean values (true/false) or strings depending on the operand. String values are case sensitive and must be enclosed in single quotes. Special characters must be escaped. Boolean and string values can only be used with the comparators <code>=</code> and <code>&lt;&gt;</code>. For example, the following filter expression searches on <code>gameSessionName</code>: "<code>FilterExpression": "gameSessionName = 'Matt\\'s Awesome Game 1'"</code>.</p></li>
    /// </ul>
    /// <p>To chain multiple conditions in a single expression, use the logical keywords <code>AND</code>, <code>OR</code>, and <code>NOT</code> and parentheses as needed. For example: <code>x AND y AND NOT z</code>, <code>NOT (x OR y)</code>.</p>
    /// <p>Session search evaluates conditions from left to right using the following precedence rules:</p>
    /// <ol>
    /// <li>
    /// <p><code>=</code>, <code>&lt;&gt;</code>, <code>&lt;</code>, <code>&gt;</code>, <code>&lt;=</code>, <code>&gt;=</code></p></li>
    /// <li>
    /// <p>Parentheses</p></li>
    /// <li>
    /// <p>NOT</p></li>
    /// <li>
    /// <p>AND</p></li>
    /// <li>
    /// <p>OR</p></li>
    /// </ol>
    /// <p>For example, this filter expression retrieves game sessions hosting at least ten players that have an open player slot: <code>"maximumSessions&gt;=10 AND hasAvailablePlayerSessions=true"</code>.</p>
    pub fn set_filter_expression(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.filter_expression = input;
        self
    }
    /// <p>String containing the search criteria for the session search. If no filter expression is included, the request returns results for all game sessions in the fleet that are in <code>ACTIVE</code> status.</p>
    /// <p>A filter expression can contain one or multiple conditions. Each condition consists of the following:</p>
    /// <ul>
    /// <li>
    /// <p><b>Operand</b> -- Name of a game session attribute. Valid values are <code>gameSessionName</code>, <code>gameSessionId</code>, <code>gameSessionProperties</code>, <code>maximumSessions</code>, <code>creationTimeMillis</code>, <code>playerSessionCount</code>, <code>hasAvailablePlayerSessions</code>.</p></li>
    /// <li>
    /// <p><b>Comparator</b> -- Valid comparators are: <code>=</code>, <code>&lt;&gt;</code>, <code>&lt;</code>, <code>&gt;</code>, <code>&lt;=</code>, <code>&gt;=</code>.</p></li>
    /// <li>
    /// <p><b>Value</b> -- Value to be searched for. Values may be numbers, boolean values (true/false) or strings depending on the operand. String values are case sensitive and must be enclosed in single quotes. Special characters must be escaped. Boolean and string values can only be used with the comparators <code>=</code> and <code>&lt;&gt;</code>. For example, the following filter expression searches on <code>gameSessionName</code>: "<code>FilterExpression": "gameSessionName = 'Matt\\'s Awesome Game 1'"</code>.</p></li>
    /// </ul>
    /// <p>To chain multiple conditions in a single expression, use the logical keywords <code>AND</code>, <code>OR</code>, and <code>NOT</code> and parentheses as needed. For example: <code>x AND y AND NOT z</code>, <code>NOT (x OR y)</code>.</p>
    /// <p>Session search evaluates conditions from left to right using the following precedence rules:</p>
    /// <ol>
    /// <li>
    /// <p><code>=</code>, <code>&lt;&gt;</code>, <code>&lt;</code>, <code>&gt;</code>, <code>&lt;=</code>, <code>&gt;=</code></p></li>
    /// <li>
    /// <p>Parentheses</p></li>
    /// <li>
    /// <p>NOT</p></li>
    /// <li>
    /// <p>AND</p></li>
    /// <li>
    /// <p>OR</p></li>
    /// </ol>
    /// <p>For example, this filter expression retrieves game sessions hosting at least ten players that have an open player slot: <code>"maximumSessions&gt;=10 AND hasAvailablePlayerSessions=true"</code>.</p>
    pub fn get_filter_expression(&self) -> &::std::option::Option<::std::string::String> {
        &self.filter_expression
    }
    /// <p>Instructions on how to sort the search results. If no sort expression is included, the request returns results in random order. A sort expression consists of the following elements:</p>
    /// <ul>
    /// <li>
    /// <p><b>Operand</b> -- Name of a game session attribute. Valid values are <code>gameSessionName</code>, <code>gameSessionId</code>, <code>gameSessionProperties</code>, <code>maximumSessions</code>, <code>creationTimeMillis</code>, <code>playerSessionCount</code>, <code>hasAvailablePlayerSessions</code>.</p></li>
    /// <li>
    /// <p><b>Order</b> -- Valid sort orders are <code>ASC</code> (ascending) and <code>DESC</code> (descending).</p></li>
    /// </ul>
    /// <p>For example, this sort expression returns the oldest active sessions first: <code>"SortExpression": "creationTimeMillis ASC"</code>. Results with a null value for the sort operand are returned at the end of the list.</p>
    pub fn sort_expression(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sort_expression = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Instructions on how to sort the search results. If no sort expression is included, the request returns results in random order. A sort expression consists of the following elements:</p>
    /// <ul>
    /// <li>
    /// <p><b>Operand</b> -- Name of a game session attribute. Valid values are <code>gameSessionName</code>, <code>gameSessionId</code>, <code>gameSessionProperties</code>, <code>maximumSessions</code>, <code>creationTimeMillis</code>, <code>playerSessionCount</code>, <code>hasAvailablePlayerSessions</code>.</p></li>
    /// <li>
    /// <p><b>Order</b> -- Valid sort orders are <code>ASC</code> (ascending) and <code>DESC</code> (descending).</p></li>
    /// </ul>
    /// <p>For example, this sort expression returns the oldest active sessions first: <code>"SortExpression": "creationTimeMillis ASC"</code>. Results with a null value for the sort operand are returned at the end of the list.</p>
    pub fn set_sort_expression(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sort_expression = input;
        self
    }
    /// <p>Instructions on how to sort the search results. If no sort expression is included, the request returns results in random order. A sort expression consists of the following elements:</p>
    /// <ul>
    /// <li>
    /// <p><b>Operand</b> -- Name of a game session attribute. Valid values are <code>gameSessionName</code>, <code>gameSessionId</code>, <code>gameSessionProperties</code>, <code>maximumSessions</code>, <code>creationTimeMillis</code>, <code>playerSessionCount</code>, <code>hasAvailablePlayerSessions</code>.</p></li>
    /// <li>
    /// <p><b>Order</b> -- Valid sort orders are <code>ASC</code> (ascending) and <code>DESC</code> (descending).</p></li>
    /// </ul>
    /// <p>For example, this sort expression returns the oldest active sessions first: <code>"SortExpression": "creationTimeMillis ASC"</code>. Results with a null value for the sort operand are returned at the end of the list.</p>
    pub fn get_sort_expression(&self) -> &::std::option::Option<::std::string::String> {
        &self.sort_expression
    }
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages. The maximum number of results returned is 20, even if this value is not set or is set higher than 20.</p>
    pub fn limit(mut self, input: i32) -> Self {
        self.limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages. The maximum number of results returned is 20, even if this value is not set or is set higher than 20.</p>
    pub fn set_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.limit = input;
        self
    }
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages. The maximum number of results returned is 20, even if this value is not set or is set higher than 20.</p>
    pub fn get_limit(&self) -> &::std::option::Option<i32> {
        &self.limit
    }
    /// <p>A token that indicates the start of the next sequential page of results. Use the token that is returned with a previous call to this operation. To start at the beginning of the result set, do not specify a value.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that indicates the start of the next sequential page of results. Use the token that is returned with a previous call to this operation. To start at the beginning of the result set, do not specify a value.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token that indicates the start of the next sequential page of results. Use the token that is returned with a previous call to this operation. To start at the beginning of the result set, do not specify a value.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`SearchGameSessionsInput`](crate::operation::search_game_sessions::SearchGameSessionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::search_game_sessions::SearchGameSessionsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::search_game_sessions::SearchGameSessionsInput {
            fleet_id: self.fleet_id,
            alias_id: self.alias_id,
            location: self.location,
            filter_expression: self.filter_expression,
            sort_expression: self.sort_expression,
            limit: self.limit,
            next_token: self.next_token,
        })
    }
}
