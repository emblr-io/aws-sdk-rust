// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRelationalDatabaseLogEventsInput {
    /// <p>The name of your database for which to get log events.</p>
    pub relational_database_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the log stream.</p>
    /// <p>Use the <code>get relational database log streams</code> operation to get a list of available log streams.</p>
    pub log_stream_name: ::std::option::Option<::std::string::String>,
    /// <p>The start of the time interval from which to get log events.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Specified in Coordinated Universal Time (UTC).</p></li>
    /// <li>
    /// <p>Specified in the Unix time format.</p>
    /// <p>For example, if you wish to use a start time of October 1, 2018, at 8 PM UTC, then you input <code>1538424000</code> as the start time.</p></li>
    /// </ul>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The end of the time interval from which to get log events.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Specified in Coordinated Universal Time (UTC).</p></li>
    /// <li>
    /// <p>Specified in the Unix time format.</p>
    /// <p>For example, if you wish to use an end time of October 1, 2018, at 8 PM UTC, then you input <code>1538424000</code> as the end time.</p></li>
    /// </ul>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Parameter to specify if the log should start from head or tail. If <code>true</code> is specified, the log event starts from the head of the log. If <code>false</code> is specified, the log event starts from the tail of the log.</p><note>
    /// <p>For PostgreSQL, the default value of <code>false</code> is the only option available.</p>
    /// </note>
    pub start_from_head: ::std::option::Option<bool>,
    /// <p>The token to advance to the next or previous page of results from your request.</p>
    /// <p>To get a page token, perform an initial <code>GetRelationalDatabaseLogEvents</code> request. If your results are paginated, the response will return a next forward token and/or next backward token that you can specify as the page token in a subsequent request.</p>
    pub page_token: ::std::option::Option<::std::string::String>,
}
impl GetRelationalDatabaseLogEventsInput {
    /// <p>The name of your database for which to get log events.</p>
    pub fn relational_database_name(&self) -> ::std::option::Option<&str> {
        self.relational_database_name.as_deref()
    }
    /// <p>The name of the log stream.</p>
    /// <p>Use the <code>get relational database log streams</code> operation to get a list of available log streams.</p>
    pub fn log_stream_name(&self) -> ::std::option::Option<&str> {
        self.log_stream_name.as_deref()
    }
    /// <p>The start of the time interval from which to get log events.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Specified in Coordinated Universal Time (UTC).</p></li>
    /// <li>
    /// <p>Specified in the Unix time format.</p>
    /// <p>For example, if you wish to use a start time of October 1, 2018, at 8 PM UTC, then you input <code>1538424000</code> as the start time.</p></li>
    /// </ul>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The end of the time interval from which to get log events.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Specified in Coordinated Universal Time (UTC).</p></li>
    /// <li>
    /// <p>Specified in the Unix time format.</p>
    /// <p>For example, if you wish to use an end time of October 1, 2018, at 8 PM UTC, then you input <code>1538424000</code> as the end time.</p></li>
    /// </ul>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
    /// <p>Parameter to specify if the log should start from head or tail. If <code>true</code> is specified, the log event starts from the head of the log. If <code>false</code> is specified, the log event starts from the tail of the log.</p><note>
    /// <p>For PostgreSQL, the default value of <code>false</code> is the only option available.</p>
    /// </note>
    pub fn start_from_head(&self) -> ::std::option::Option<bool> {
        self.start_from_head
    }
    /// <p>The token to advance to the next or previous page of results from your request.</p>
    /// <p>To get a page token, perform an initial <code>GetRelationalDatabaseLogEvents</code> request. If your results are paginated, the response will return a next forward token and/or next backward token that you can specify as the page token in a subsequent request.</p>
    pub fn page_token(&self) -> ::std::option::Option<&str> {
        self.page_token.as_deref()
    }
}
impl GetRelationalDatabaseLogEventsInput {
    /// Creates a new builder-style object to manufacture [`GetRelationalDatabaseLogEventsInput`](crate::operation::get_relational_database_log_events::GetRelationalDatabaseLogEventsInput).
    pub fn builder() -> crate::operation::get_relational_database_log_events::builders::GetRelationalDatabaseLogEventsInputBuilder {
        crate::operation::get_relational_database_log_events::builders::GetRelationalDatabaseLogEventsInputBuilder::default()
    }
}

/// A builder for [`GetRelationalDatabaseLogEventsInput`](crate::operation::get_relational_database_log_events::GetRelationalDatabaseLogEventsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRelationalDatabaseLogEventsInputBuilder {
    pub(crate) relational_database_name: ::std::option::Option<::std::string::String>,
    pub(crate) log_stream_name: ::std::option::Option<::std::string::String>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) start_from_head: ::std::option::Option<bool>,
    pub(crate) page_token: ::std::option::Option<::std::string::String>,
}
impl GetRelationalDatabaseLogEventsInputBuilder {
    /// <p>The name of your database for which to get log events.</p>
    /// This field is required.
    pub fn relational_database_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.relational_database_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of your database for which to get log events.</p>
    pub fn set_relational_database_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.relational_database_name = input;
        self
    }
    /// <p>The name of your database for which to get log events.</p>
    pub fn get_relational_database_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.relational_database_name
    }
    /// <p>The name of the log stream.</p>
    /// <p>Use the <code>get relational database log streams</code> operation to get a list of available log streams.</p>
    /// This field is required.
    pub fn log_stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_stream_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the log stream.</p>
    /// <p>Use the <code>get relational database log streams</code> operation to get a list of available log streams.</p>
    pub fn set_log_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_stream_name = input;
        self
    }
    /// <p>The name of the log stream.</p>
    /// <p>Use the <code>get relational database log streams</code> operation to get a list of available log streams.</p>
    pub fn get_log_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_stream_name
    }
    /// <p>The start of the time interval from which to get log events.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Specified in Coordinated Universal Time (UTC).</p></li>
    /// <li>
    /// <p>Specified in the Unix time format.</p>
    /// <p>For example, if you wish to use a start time of October 1, 2018, at 8 PM UTC, then you input <code>1538424000</code> as the start time.</p></li>
    /// </ul>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The start of the time interval from which to get log events.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Specified in Coordinated Universal Time (UTC).</p></li>
    /// <li>
    /// <p>Specified in the Unix time format.</p>
    /// <p>For example, if you wish to use a start time of October 1, 2018, at 8 PM UTC, then you input <code>1538424000</code> as the start time.</p></li>
    /// </ul>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The start of the time interval from which to get log events.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Specified in Coordinated Universal Time (UTC).</p></li>
    /// <li>
    /// <p>Specified in the Unix time format.</p>
    /// <p>For example, if you wish to use a start time of October 1, 2018, at 8 PM UTC, then you input <code>1538424000</code> as the start time.</p></li>
    /// </ul>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The end of the time interval from which to get log events.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Specified in Coordinated Universal Time (UTC).</p></li>
    /// <li>
    /// <p>Specified in the Unix time format.</p>
    /// <p>For example, if you wish to use an end time of October 1, 2018, at 8 PM UTC, then you input <code>1538424000</code> as the end time.</p></li>
    /// </ul>
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The end of the time interval from which to get log events.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Specified in Coordinated Universal Time (UTC).</p></li>
    /// <li>
    /// <p>Specified in the Unix time format.</p>
    /// <p>For example, if you wish to use an end time of October 1, 2018, at 8 PM UTC, then you input <code>1538424000</code> as the end time.</p></li>
    /// </ul>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The end of the time interval from which to get log events.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Specified in Coordinated Universal Time (UTC).</p></li>
    /// <li>
    /// <p>Specified in the Unix time format.</p>
    /// <p>For example, if you wish to use an end time of October 1, 2018, at 8 PM UTC, then you input <code>1538424000</code> as the end time.</p></li>
    /// </ul>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// <p>Parameter to specify if the log should start from head or tail. If <code>true</code> is specified, the log event starts from the head of the log. If <code>false</code> is specified, the log event starts from the tail of the log.</p><note>
    /// <p>For PostgreSQL, the default value of <code>false</code> is the only option available.</p>
    /// </note>
    pub fn start_from_head(mut self, input: bool) -> Self {
        self.start_from_head = ::std::option::Option::Some(input);
        self
    }
    /// <p>Parameter to specify if the log should start from head or tail. If <code>true</code> is specified, the log event starts from the head of the log. If <code>false</code> is specified, the log event starts from the tail of the log.</p><note>
    /// <p>For PostgreSQL, the default value of <code>false</code> is the only option available.</p>
    /// </note>
    pub fn set_start_from_head(mut self, input: ::std::option::Option<bool>) -> Self {
        self.start_from_head = input;
        self
    }
    /// <p>Parameter to specify if the log should start from head or tail. If <code>true</code> is specified, the log event starts from the head of the log. If <code>false</code> is specified, the log event starts from the tail of the log.</p><note>
    /// <p>For PostgreSQL, the default value of <code>false</code> is the only option available.</p>
    /// </note>
    pub fn get_start_from_head(&self) -> &::std::option::Option<bool> {
        &self.start_from_head
    }
    /// <p>The token to advance to the next or previous page of results from your request.</p>
    /// <p>To get a page token, perform an initial <code>GetRelationalDatabaseLogEvents</code> request. If your results are paginated, the response will return a next forward token and/or next backward token that you can specify as the page token in a subsequent request.</p>
    pub fn page_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.page_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to advance to the next or previous page of results from your request.</p>
    /// <p>To get a page token, perform an initial <code>GetRelationalDatabaseLogEvents</code> request. If your results are paginated, the response will return a next forward token and/or next backward token that you can specify as the page token in a subsequent request.</p>
    pub fn set_page_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.page_token = input;
        self
    }
    /// <p>The token to advance to the next or previous page of results from your request.</p>
    /// <p>To get a page token, perform an initial <code>GetRelationalDatabaseLogEvents</code> request. If your results are paginated, the response will return a next forward token and/or next backward token that you can specify as the page token in a subsequent request.</p>
    pub fn get_page_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.page_token
    }
    /// Consumes the builder and constructs a [`GetRelationalDatabaseLogEventsInput`](crate::operation::get_relational_database_log_events::GetRelationalDatabaseLogEventsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_relational_database_log_events::GetRelationalDatabaseLogEventsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_relational_database_log_events::GetRelationalDatabaseLogEventsInput {
                relational_database_name: self.relational_database_name,
                log_stream_name: self.log_stream_name,
                start_time: self.start_time,
                end_time: self.end_time,
                start_from_head: self.start_from_head,
                page_token: self.page_token,
            },
        )
    }
}
