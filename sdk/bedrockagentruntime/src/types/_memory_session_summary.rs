// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details of a session summary.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MemorySessionSummary {
    /// <p>The unique identifier of the memory where the session summary is stored.</p>
    pub memory_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier for this session.</p>
    pub session_id: ::std::option::Option<::std::string::String>,
    /// <p>The start time for this session.</p>
    pub session_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time when the memory duration for the session is set to end.</p>
    pub session_expiry_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The summarized text for this session.</p>
    pub summary_text: ::std::option::Option<::std::string::String>,
}
impl MemorySessionSummary {
    /// <p>The unique identifier of the memory where the session summary is stored.</p>
    pub fn memory_id(&self) -> ::std::option::Option<&str> {
        self.memory_id.as_deref()
    }
    /// <p>The identifier for this session.</p>
    pub fn session_id(&self) -> ::std::option::Option<&str> {
        self.session_id.as_deref()
    }
    /// <p>The start time for this session.</p>
    pub fn session_start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.session_start_time.as_ref()
    }
    /// <p>The time when the memory duration for the session is set to end.</p>
    pub fn session_expiry_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.session_expiry_time.as_ref()
    }
    /// <p>The summarized text for this session.</p>
    pub fn summary_text(&self) -> ::std::option::Option<&str> {
        self.summary_text.as_deref()
    }
}
impl MemorySessionSummary {
    /// Creates a new builder-style object to manufacture [`MemorySessionSummary`](crate::types::MemorySessionSummary).
    pub fn builder() -> crate::types::builders::MemorySessionSummaryBuilder {
        crate::types::builders::MemorySessionSummaryBuilder::default()
    }
}

/// A builder for [`MemorySessionSummary`](crate::types::MemorySessionSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MemorySessionSummaryBuilder {
    pub(crate) memory_id: ::std::option::Option<::std::string::String>,
    pub(crate) session_id: ::std::option::Option<::std::string::String>,
    pub(crate) session_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) session_expiry_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) summary_text: ::std::option::Option<::std::string::String>,
}
impl MemorySessionSummaryBuilder {
    /// <p>The unique identifier of the memory where the session summary is stored.</p>
    pub fn memory_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.memory_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the memory where the session summary is stored.</p>
    pub fn set_memory_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.memory_id = input;
        self
    }
    /// <p>The unique identifier of the memory where the session summary is stored.</p>
    pub fn get_memory_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.memory_id
    }
    /// <p>The identifier for this session.</p>
    pub fn session_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.session_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for this session.</p>
    pub fn set_session_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.session_id = input;
        self
    }
    /// <p>The identifier for this session.</p>
    pub fn get_session_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.session_id
    }
    /// <p>The start time for this session.</p>
    pub fn session_start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.session_start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The start time for this session.</p>
    pub fn set_session_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.session_start_time = input;
        self
    }
    /// <p>The start time for this session.</p>
    pub fn get_session_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.session_start_time
    }
    /// <p>The time when the memory duration for the session is set to end.</p>
    pub fn session_expiry_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.session_expiry_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time when the memory duration for the session is set to end.</p>
    pub fn set_session_expiry_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.session_expiry_time = input;
        self
    }
    /// <p>The time when the memory duration for the session is set to end.</p>
    pub fn get_session_expiry_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.session_expiry_time
    }
    /// <p>The summarized text for this session.</p>
    pub fn summary_text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.summary_text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The summarized text for this session.</p>
    pub fn set_summary_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.summary_text = input;
        self
    }
    /// <p>The summarized text for this session.</p>
    pub fn get_summary_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.summary_text
    }
    /// Consumes the builder and constructs a [`MemorySessionSummary`](crate::types::MemorySessionSummary).
    pub fn build(self) -> crate::types::MemorySessionSummary {
        crate::types::MemorySessionSummary {
            memory_id: self.memory_id,
            session_id: self.session_id,
            session_start_time: self.session_start_time,
            session_expiry_time: self.session_expiry_time,
            summary_text: self.summary_text,
        }
    }
}
