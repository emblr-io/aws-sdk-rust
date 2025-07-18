// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListFunctionUrlConfigsOutput {
    /// <p>A list of function URL configurations.</p>
    pub function_url_configs: ::std::vec::Vec<crate::types::FunctionUrlConfig>,
    /// <p>The pagination token that's included if more results are available.</p>
    pub next_marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListFunctionUrlConfigsOutput {
    /// <p>A list of function URL configurations.</p>
    pub fn function_url_configs(&self) -> &[crate::types::FunctionUrlConfig] {
        use std::ops::Deref;
        self.function_url_configs.deref()
    }
    /// <p>The pagination token that's included if more results are available.</p>
    pub fn next_marker(&self) -> ::std::option::Option<&str> {
        self.next_marker.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListFunctionUrlConfigsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListFunctionUrlConfigsOutput {
    /// Creates a new builder-style object to manufacture [`ListFunctionUrlConfigsOutput`](crate::operation::list_function_url_configs::ListFunctionUrlConfigsOutput).
    pub fn builder() -> crate::operation::list_function_url_configs::builders::ListFunctionUrlConfigsOutputBuilder {
        crate::operation::list_function_url_configs::builders::ListFunctionUrlConfigsOutputBuilder::default()
    }
}

/// A builder for [`ListFunctionUrlConfigsOutput`](crate::operation::list_function_url_configs::ListFunctionUrlConfigsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListFunctionUrlConfigsOutputBuilder {
    pub(crate) function_url_configs: ::std::option::Option<::std::vec::Vec<crate::types::FunctionUrlConfig>>,
    pub(crate) next_marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListFunctionUrlConfigsOutputBuilder {
    /// Appends an item to `function_url_configs`.
    ///
    /// To override the contents of this collection use [`set_function_url_configs`](Self::set_function_url_configs).
    ///
    /// <p>A list of function URL configurations.</p>
    pub fn function_url_configs(mut self, input: crate::types::FunctionUrlConfig) -> Self {
        let mut v = self.function_url_configs.unwrap_or_default();
        v.push(input);
        self.function_url_configs = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of function URL configurations.</p>
    pub fn set_function_url_configs(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FunctionUrlConfig>>) -> Self {
        self.function_url_configs = input;
        self
    }
    /// <p>A list of function URL configurations.</p>
    pub fn get_function_url_configs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FunctionUrlConfig>> {
        &self.function_url_configs
    }
    /// <p>The pagination token that's included if more results are available.</p>
    pub fn next_marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token that's included if more results are available.</p>
    pub fn set_next_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_marker = input;
        self
    }
    /// <p>The pagination token that's included if more results are available.</p>
    pub fn get_next_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_marker
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListFunctionUrlConfigsOutput`](crate::operation::list_function_url_configs::ListFunctionUrlConfigsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`function_url_configs`](crate::operation::list_function_url_configs::builders::ListFunctionUrlConfigsOutputBuilder::function_url_configs)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_function_url_configs::ListFunctionUrlConfigsOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_function_url_configs::ListFunctionUrlConfigsOutput {
            function_url_configs: self.function_url_configs.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "function_url_configs",
                    "function_url_configs was not specified but it is required when building ListFunctionUrlConfigsOutput",
                )
            })?,
            next_marker: self.next_marker,
            _request_id: self._request_id,
        })
    }
}
