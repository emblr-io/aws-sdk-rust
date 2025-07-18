// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This structure contains details about a saved CloudWatch Logs Insights query definition.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct QueryDefinition {
    /// <p>The query language used for this query. For more information about the query languages that CloudWatch Logs supports, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_AnalyzeLogData_Languages.html">Supported query languages</a>.</p>
    pub query_language: ::std::option::Option<crate::types::QueryLanguage>,
    /// <p>The unique ID of the query definition.</p>
    pub query_definition_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the query definition.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The query string to use for this definition. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html">CloudWatch Logs Insights Query Syntax</a>.</p>
    pub query_string: ::std::option::Option<::std::string::String>,
    /// <p>The date that the query definition was most recently modified.</p>
    pub last_modified: ::std::option::Option<i64>,
    /// <p>If this query definition contains a list of log groups that it is limited to, that list appears here.</p>
    pub log_group_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl QueryDefinition {
    /// <p>The query language used for this query. For more information about the query languages that CloudWatch Logs supports, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_AnalyzeLogData_Languages.html">Supported query languages</a>.</p>
    pub fn query_language(&self) -> ::std::option::Option<&crate::types::QueryLanguage> {
        self.query_language.as_ref()
    }
    /// <p>The unique ID of the query definition.</p>
    pub fn query_definition_id(&self) -> ::std::option::Option<&str> {
        self.query_definition_id.as_deref()
    }
    /// <p>The name of the query definition.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The query string to use for this definition. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html">CloudWatch Logs Insights Query Syntax</a>.</p>
    pub fn query_string(&self) -> ::std::option::Option<&str> {
        self.query_string.as_deref()
    }
    /// <p>The date that the query definition was most recently modified.</p>
    pub fn last_modified(&self) -> ::std::option::Option<i64> {
        self.last_modified
    }
    /// <p>If this query definition contains a list of log groups that it is limited to, that list appears here.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.log_group_names.is_none()`.
    pub fn log_group_names(&self) -> &[::std::string::String] {
        self.log_group_names.as_deref().unwrap_or_default()
    }
}
impl QueryDefinition {
    /// Creates a new builder-style object to manufacture [`QueryDefinition`](crate::types::QueryDefinition).
    pub fn builder() -> crate::types::builders::QueryDefinitionBuilder {
        crate::types::builders::QueryDefinitionBuilder::default()
    }
}

/// A builder for [`QueryDefinition`](crate::types::QueryDefinition).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct QueryDefinitionBuilder {
    pub(crate) query_language: ::std::option::Option<crate::types::QueryLanguage>,
    pub(crate) query_definition_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) query_string: ::std::option::Option<::std::string::String>,
    pub(crate) last_modified: ::std::option::Option<i64>,
    pub(crate) log_group_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl QueryDefinitionBuilder {
    /// <p>The query language used for this query. For more information about the query languages that CloudWatch Logs supports, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_AnalyzeLogData_Languages.html">Supported query languages</a>.</p>
    pub fn query_language(mut self, input: crate::types::QueryLanguage) -> Self {
        self.query_language = ::std::option::Option::Some(input);
        self
    }
    /// <p>The query language used for this query. For more information about the query languages that CloudWatch Logs supports, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_AnalyzeLogData_Languages.html">Supported query languages</a>.</p>
    pub fn set_query_language(mut self, input: ::std::option::Option<crate::types::QueryLanguage>) -> Self {
        self.query_language = input;
        self
    }
    /// <p>The query language used for this query. For more information about the query languages that CloudWatch Logs supports, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_AnalyzeLogData_Languages.html">Supported query languages</a>.</p>
    pub fn get_query_language(&self) -> &::std::option::Option<crate::types::QueryLanguage> {
        &self.query_language
    }
    /// <p>The unique ID of the query definition.</p>
    pub fn query_definition_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.query_definition_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID of the query definition.</p>
    pub fn set_query_definition_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.query_definition_id = input;
        self
    }
    /// <p>The unique ID of the query definition.</p>
    pub fn get_query_definition_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.query_definition_id
    }
    /// <p>The name of the query definition.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the query definition.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the query definition.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The query string to use for this definition. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html">CloudWatch Logs Insights Query Syntax</a>.</p>
    pub fn query_string(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.query_string = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The query string to use for this definition. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html">CloudWatch Logs Insights Query Syntax</a>.</p>
    pub fn set_query_string(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.query_string = input;
        self
    }
    /// <p>The query string to use for this definition. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html">CloudWatch Logs Insights Query Syntax</a>.</p>
    pub fn get_query_string(&self) -> &::std::option::Option<::std::string::String> {
        &self.query_string
    }
    /// <p>The date that the query definition was most recently modified.</p>
    pub fn last_modified(mut self, input: i64) -> Self {
        self.last_modified = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date that the query definition was most recently modified.</p>
    pub fn set_last_modified(mut self, input: ::std::option::Option<i64>) -> Self {
        self.last_modified = input;
        self
    }
    /// <p>The date that the query definition was most recently modified.</p>
    pub fn get_last_modified(&self) -> &::std::option::Option<i64> {
        &self.last_modified
    }
    /// Appends an item to `log_group_names`.
    ///
    /// To override the contents of this collection use [`set_log_group_names`](Self::set_log_group_names).
    ///
    /// <p>If this query definition contains a list of log groups that it is limited to, that list appears here.</p>
    pub fn log_group_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.log_group_names.unwrap_or_default();
        v.push(input.into());
        self.log_group_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>If this query definition contains a list of log groups that it is limited to, that list appears here.</p>
    pub fn set_log_group_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.log_group_names = input;
        self
    }
    /// <p>If this query definition contains a list of log groups that it is limited to, that list appears here.</p>
    pub fn get_log_group_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.log_group_names
    }
    /// Consumes the builder and constructs a [`QueryDefinition`](crate::types::QueryDefinition).
    pub fn build(self) -> crate::types::QueryDefinition {
        crate::types::QueryDefinition {
            query_language: self.query_language,
            query_definition_id: self.query_definition_id,
            name: self.name,
            query_string: self.query_string,
            last_modified: self.last_modified,
            log_group_names: self.log_group_names,
        }
    }
}
