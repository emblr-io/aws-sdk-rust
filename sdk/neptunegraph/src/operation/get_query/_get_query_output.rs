// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetQueryOutput {
    /// <p>The ID of the query in question.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The query in question.</p>
    pub query_string: ::std::option::Option<::std::string::String>,
    /// <p>Indicates how long the query waited, in milliseconds.</p>
    pub waited: ::std::option::Option<i32>,
    /// <p>The number of milliseconds the query has been running.</p>
    pub elapsed: ::std::option::Option<i32>,
    /// <p>State of the query.</p>
    pub state: ::std::option::Option<crate::types::QueryState>,
    _request_id: Option<String>,
}
impl GetQueryOutput {
    /// <p>The ID of the query in question.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The query in question.</p>
    pub fn query_string(&self) -> ::std::option::Option<&str> {
        self.query_string.as_deref()
    }
    /// <p>Indicates how long the query waited, in milliseconds.</p>
    pub fn waited(&self) -> ::std::option::Option<i32> {
        self.waited
    }
    /// <p>The number of milliseconds the query has been running.</p>
    pub fn elapsed(&self) -> ::std::option::Option<i32> {
        self.elapsed
    }
    /// <p>State of the query.</p>
    pub fn state(&self) -> ::std::option::Option<&crate::types::QueryState> {
        self.state.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetQueryOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetQueryOutput {
    /// Creates a new builder-style object to manufacture [`GetQueryOutput`](crate::operation::get_query::GetQueryOutput).
    pub fn builder() -> crate::operation::get_query::builders::GetQueryOutputBuilder {
        crate::operation::get_query::builders::GetQueryOutputBuilder::default()
    }
}

/// A builder for [`GetQueryOutput`](crate::operation::get_query::GetQueryOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetQueryOutputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) query_string: ::std::option::Option<::std::string::String>,
    pub(crate) waited: ::std::option::Option<i32>,
    pub(crate) elapsed: ::std::option::Option<i32>,
    pub(crate) state: ::std::option::Option<crate::types::QueryState>,
    _request_id: Option<String>,
}
impl GetQueryOutputBuilder {
    /// <p>The ID of the query in question.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the query in question.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the query in question.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The query in question.</p>
    pub fn query_string(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.query_string = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The query in question.</p>
    pub fn set_query_string(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.query_string = input;
        self
    }
    /// <p>The query in question.</p>
    pub fn get_query_string(&self) -> &::std::option::Option<::std::string::String> {
        &self.query_string
    }
    /// <p>Indicates how long the query waited, in milliseconds.</p>
    pub fn waited(mut self, input: i32) -> Self {
        self.waited = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates how long the query waited, in milliseconds.</p>
    pub fn set_waited(mut self, input: ::std::option::Option<i32>) -> Self {
        self.waited = input;
        self
    }
    /// <p>Indicates how long the query waited, in milliseconds.</p>
    pub fn get_waited(&self) -> &::std::option::Option<i32> {
        &self.waited
    }
    /// <p>The number of milliseconds the query has been running.</p>
    pub fn elapsed(mut self, input: i32) -> Self {
        self.elapsed = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of milliseconds the query has been running.</p>
    pub fn set_elapsed(mut self, input: ::std::option::Option<i32>) -> Self {
        self.elapsed = input;
        self
    }
    /// <p>The number of milliseconds the query has been running.</p>
    pub fn get_elapsed(&self) -> &::std::option::Option<i32> {
        &self.elapsed
    }
    /// <p>State of the query.</p>
    pub fn state(mut self, input: crate::types::QueryState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>State of the query.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::QueryState>) -> Self {
        self.state = input;
        self
    }
    /// <p>State of the query.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::QueryState> {
        &self.state
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetQueryOutput`](crate::operation::get_query::GetQueryOutput).
    pub fn build(self) -> crate::operation::get_query::GetQueryOutput {
        crate::operation::get_query::GetQueryOutput {
            id: self.id,
            query_string: self.query_string,
            waited: self.waited,
            elapsed: self.elapsed,
            state: self.state,
            _request_id: self._request_id,
        }
    }
}
