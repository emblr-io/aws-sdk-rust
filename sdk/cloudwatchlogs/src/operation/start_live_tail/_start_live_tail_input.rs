// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartLiveTailInput {
    /// <p>An array where each item in the array is a log group to include in the Live Tail session.</p>
    /// <p>Specify each log group by its ARN.</p>
    /// <p>If you specify an ARN, the ARN can't end with an asterisk (*).</p><note>
    /// <p>You can include up to 10 log groups.</p>
    /// </note>
    pub log_group_identifiers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>If you specify this parameter, then only log events in the log streams that you specify here are included in the Live Tail session.</p>
    /// <p>If you specify this field, you can't also specify the <code>logStreamNamePrefixes</code> field.</p><note>
    /// <p>You can specify this parameter only if you specify only one log group in <code>logGroupIdentifiers</code>.</p>
    /// </note>
    pub log_stream_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>If you specify this parameter, then only log events in the log streams that have names that start with the prefixes that you specify here are included in the Live Tail session.</p>
    /// <p>If you specify this field, you can't also specify the <code>logStreamNames</code> field.</p><note>
    /// <p>You can specify this parameter only if you specify only one log group in <code>logGroupIdentifiers</code>.</p>
    /// </note>
    pub log_stream_name_prefixes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>An optional pattern to use to filter the results to include only log events that match the pattern. For example, a filter pattern of <code>error 404</code> causes only log events that include both <code>error</code> and <code>404</code> to be included in the Live Tail stream.</p>
    /// <p>Regular expression filter patterns are supported.</p>
    /// <p>For more information about filter pattern syntax, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html">Filter and Pattern Syntax</a>.</p>
    pub log_event_filter_pattern: ::std::option::Option<::std::string::String>,
}
impl StartLiveTailInput {
    /// <p>An array where each item in the array is a log group to include in the Live Tail session.</p>
    /// <p>Specify each log group by its ARN.</p>
    /// <p>If you specify an ARN, the ARN can't end with an asterisk (*).</p><note>
    /// <p>You can include up to 10 log groups.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.log_group_identifiers.is_none()`.
    pub fn log_group_identifiers(&self) -> &[::std::string::String] {
        self.log_group_identifiers.as_deref().unwrap_or_default()
    }
    /// <p>If you specify this parameter, then only log events in the log streams that you specify here are included in the Live Tail session.</p>
    /// <p>If you specify this field, you can't also specify the <code>logStreamNamePrefixes</code> field.</p><note>
    /// <p>You can specify this parameter only if you specify only one log group in <code>logGroupIdentifiers</code>.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.log_stream_names.is_none()`.
    pub fn log_stream_names(&self) -> &[::std::string::String] {
        self.log_stream_names.as_deref().unwrap_or_default()
    }
    /// <p>If you specify this parameter, then only log events in the log streams that have names that start with the prefixes that you specify here are included in the Live Tail session.</p>
    /// <p>If you specify this field, you can't also specify the <code>logStreamNames</code> field.</p><note>
    /// <p>You can specify this parameter only if you specify only one log group in <code>logGroupIdentifiers</code>.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.log_stream_name_prefixes.is_none()`.
    pub fn log_stream_name_prefixes(&self) -> &[::std::string::String] {
        self.log_stream_name_prefixes.as_deref().unwrap_or_default()
    }
    /// <p>An optional pattern to use to filter the results to include only log events that match the pattern. For example, a filter pattern of <code>error 404</code> causes only log events that include both <code>error</code> and <code>404</code> to be included in the Live Tail stream.</p>
    /// <p>Regular expression filter patterns are supported.</p>
    /// <p>For more information about filter pattern syntax, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html">Filter and Pattern Syntax</a>.</p>
    pub fn log_event_filter_pattern(&self) -> ::std::option::Option<&str> {
        self.log_event_filter_pattern.as_deref()
    }
}
impl StartLiveTailInput {
    /// Creates a new builder-style object to manufacture [`StartLiveTailInput`](crate::operation::start_live_tail::StartLiveTailInput).
    pub fn builder() -> crate::operation::start_live_tail::builders::StartLiveTailInputBuilder {
        crate::operation::start_live_tail::builders::StartLiveTailInputBuilder::default()
    }
}

/// A builder for [`StartLiveTailInput`](crate::operation::start_live_tail::StartLiveTailInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartLiveTailInputBuilder {
    pub(crate) log_group_identifiers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) log_stream_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) log_stream_name_prefixes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) log_event_filter_pattern: ::std::option::Option<::std::string::String>,
}
impl StartLiveTailInputBuilder {
    /// Appends an item to `log_group_identifiers`.
    ///
    /// To override the contents of this collection use [`set_log_group_identifiers`](Self::set_log_group_identifiers).
    ///
    /// <p>An array where each item in the array is a log group to include in the Live Tail session.</p>
    /// <p>Specify each log group by its ARN.</p>
    /// <p>If you specify an ARN, the ARN can't end with an asterisk (*).</p><note>
    /// <p>You can include up to 10 log groups.</p>
    /// </note>
    pub fn log_group_identifiers(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.log_group_identifiers.unwrap_or_default();
        v.push(input.into());
        self.log_group_identifiers = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array where each item in the array is a log group to include in the Live Tail session.</p>
    /// <p>Specify each log group by its ARN.</p>
    /// <p>If you specify an ARN, the ARN can't end with an asterisk (*).</p><note>
    /// <p>You can include up to 10 log groups.</p>
    /// </note>
    pub fn set_log_group_identifiers(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.log_group_identifiers = input;
        self
    }
    /// <p>An array where each item in the array is a log group to include in the Live Tail session.</p>
    /// <p>Specify each log group by its ARN.</p>
    /// <p>If you specify an ARN, the ARN can't end with an asterisk (*).</p><note>
    /// <p>You can include up to 10 log groups.</p>
    /// </note>
    pub fn get_log_group_identifiers(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.log_group_identifiers
    }
    /// Appends an item to `log_stream_names`.
    ///
    /// To override the contents of this collection use [`set_log_stream_names`](Self::set_log_stream_names).
    ///
    /// <p>If you specify this parameter, then only log events in the log streams that you specify here are included in the Live Tail session.</p>
    /// <p>If you specify this field, you can't also specify the <code>logStreamNamePrefixes</code> field.</p><note>
    /// <p>You can specify this parameter only if you specify only one log group in <code>logGroupIdentifiers</code>.</p>
    /// </note>
    pub fn log_stream_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.log_stream_names.unwrap_or_default();
        v.push(input.into());
        self.log_stream_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>If you specify this parameter, then only log events in the log streams that you specify here are included in the Live Tail session.</p>
    /// <p>If you specify this field, you can't also specify the <code>logStreamNamePrefixes</code> field.</p><note>
    /// <p>You can specify this parameter only if you specify only one log group in <code>logGroupIdentifiers</code>.</p>
    /// </note>
    pub fn set_log_stream_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.log_stream_names = input;
        self
    }
    /// <p>If you specify this parameter, then only log events in the log streams that you specify here are included in the Live Tail session.</p>
    /// <p>If you specify this field, you can't also specify the <code>logStreamNamePrefixes</code> field.</p><note>
    /// <p>You can specify this parameter only if you specify only one log group in <code>logGroupIdentifiers</code>.</p>
    /// </note>
    pub fn get_log_stream_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.log_stream_names
    }
    /// Appends an item to `log_stream_name_prefixes`.
    ///
    /// To override the contents of this collection use [`set_log_stream_name_prefixes`](Self::set_log_stream_name_prefixes).
    ///
    /// <p>If you specify this parameter, then only log events in the log streams that have names that start with the prefixes that you specify here are included in the Live Tail session.</p>
    /// <p>If you specify this field, you can't also specify the <code>logStreamNames</code> field.</p><note>
    /// <p>You can specify this parameter only if you specify only one log group in <code>logGroupIdentifiers</code>.</p>
    /// </note>
    pub fn log_stream_name_prefixes(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.log_stream_name_prefixes.unwrap_or_default();
        v.push(input.into());
        self.log_stream_name_prefixes = ::std::option::Option::Some(v);
        self
    }
    /// <p>If you specify this parameter, then only log events in the log streams that have names that start with the prefixes that you specify here are included in the Live Tail session.</p>
    /// <p>If you specify this field, you can't also specify the <code>logStreamNames</code> field.</p><note>
    /// <p>You can specify this parameter only if you specify only one log group in <code>logGroupIdentifiers</code>.</p>
    /// </note>
    pub fn set_log_stream_name_prefixes(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.log_stream_name_prefixes = input;
        self
    }
    /// <p>If you specify this parameter, then only log events in the log streams that have names that start with the prefixes that you specify here are included in the Live Tail session.</p>
    /// <p>If you specify this field, you can't also specify the <code>logStreamNames</code> field.</p><note>
    /// <p>You can specify this parameter only if you specify only one log group in <code>logGroupIdentifiers</code>.</p>
    /// </note>
    pub fn get_log_stream_name_prefixes(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.log_stream_name_prefixes
    }
    /// <p>An optional pattern to use to filter the results to include only log events that match the pattern. For example, a filter pattern of <code>error 404</code> causes only log events that include both <code>error</code> and <code>404</code> to be included in the Live Tail stream.</p>
    /// <p>Regular expression filter patterns are supported.</p>
    /// <p>For more information about filter pattern syntax, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html">Filter and Pattern Syntax</a>.</p>
    pub fn log_event_filter_pattern(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_event_filter_pattern = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional pattern to use to filter the results to include only log events that match the pattern. For example, a filter pattern of <code>error 404</code> causes only log events that include both <code>error</code> and <code>404</code> to be included in the Live Tail stream.</p>
    /// <p>Regular expression filter patterns are supported.</p>
    /// <p>For more information about filter pattern syntax, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html">Filter and Pattern Syntax</a>.</p>
    pub fn set_log_event_filter_pattern(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_event_filter_pattern = input;
        self
    }
    /// <p>An optional pattern to use to filter the results to include only log events that match the pattern. For example, a filter pattern of <code>error 404</code> causes only log events that include both <code>error</code> and <code>404</code> to be included in the Live Tail stream.</p>
    /// <p>Regular expression filter patterns are supported.</p>
    /// <p>For more information about filter pattern syntax, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html">Filter and Pattern Syntax</a>.</p>
    pub fn get_log_event_filter_pattern(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_event_filter_pattern
    }
    /// Consumes the builder and constructs a [`StartLiveTailInput`](crate::operation::start_live_tail::StartLiveTailInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_live_tail::StartLiveTailInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::start_live_tail::StartLiveTailInput {
            log_group_identifiers: self.log_group_identifiers,
            log_stream_names: self.log_stream_names,
            log_stream_name_prefixes: self.log_stream_name_prefixes,
            log_event_filter_pattern: self.log_event_filter_pattern,
        })
    }
}
