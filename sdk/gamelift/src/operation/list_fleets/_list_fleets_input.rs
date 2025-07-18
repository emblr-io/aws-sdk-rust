// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListFleetsInput {
    /// <p>A unique identifier for the build to request fleets for. Use this parameter to return only fleets using a specified build. Use either the build ID or ARN value.</p>
    pub build_id: ::std::option::Option<::std::string::String>,
    /// <p>A unique identifier for the Realtime script to request fleets for. Use this parameter to return only fleets using a specified script. Use either the script ID or ARN value.</p>
    pub script_id: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages.</p>
    pub limit: ::std::option::Option<i32>,
    /// <p>A token that indicates the start of the next sequential page of results. Use the token that is returned with a previous call to this operation. To start at the beginning of the result set, do not specify a value.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListFleetsInput {
    /// <p>A unique identifier for the build to request fleets for. Use this parameter to return only fleets using a specified build. Use either the build ID or ARN value.</p>
    pub fn build_id(&self) -> ::std::option::Option<&str> {
        self.build_id.as_deref()
    }
    /// <p>A unique identifier for the Realtime script to request fleets for. Use this parameter to return only fleets using a specified script. Use either the script ID or ARN value.</p>
    pub fn script_id(&self) -> ::std::option::Option<&str> {
        self.script_id.as_deref()
    }
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages.</p>
    pub fn limit(&self) -> ::std::option::Option<i32> {
        self.limit
    }
    /// <p>A token that indicates the start of the next sequential page of results. Use the token that is returned with a previous call to this operation. To start at the beginning of the result set, do not specify a value.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListFleetsInput {
    /// Creates a new builder-style object to manufacture [`ListFleetsInput`](crate::operation::list_fleets::ListFleetsInput).
    pub fn builder() -> crate::operation::list_fleets::builders::ListFleetsInputBuilder {
        crate::operation::list_fleets::builders::ListFleetsInputBuilder::default()
    }
}

/// A builder for [`ListFleetsInput`](crate::operation::list_fleets::ListFleetsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListFleetsInputBuilder {
    pub(crate) build_id: ::std::option::Option<::std::string::String>,
    pub(crate) script_id: ::std::option::Option<::std::string::String>,
    pub(crate) limit: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListFleetsInputBuilder {
    /// <p>A unique identifier for the build to request fleets for. Use this parameter to return only fleets using a specified build. Use either the build ID or ARN value.</p>
    pub fn build_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.build_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the build to request fleets for. Use this parameter to return only fleets using a specified build. Use either the build ID or ARN value.</p>
    pub fn set_build_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.build_id = input;
        self
    }
    /// <p>A unique identifier for the build to request fleets for. Use this parameter to return only fleets using a specified build. Use either the build ID or ARN value.</p>
    pub fn get_build_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.build_id
    }
    /// <p>A unique identifier for the Realtime script to request fleets for. Use this parameter to return only fleets using a specified script. Use either the script ID or ARN value.</p>
    pub fn script_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.script_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the Realtime script to request fleets for. Use this parameter to return only fleets using a specified script. Use either the script ID or ARN value.</p>
    pub fn set_script_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.script_id = input;
        self
    }
    /// <p>A unique identifier for the Realtime script to request fleets for. Use this parameter to return only fleets using a specified script. Use either the script ID or ARN value.</p>
    pub fn get_script_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.script_id
    }
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages.</p>
    pub fn limit(mut self, input: i32) -> Self {
        self.limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages.</p>
    pub fn set_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.limit = input;
        self
    }
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages.</p>
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
    /// Consumes the builder and constructs a [`ListFleetsInput`](crate::operation::list_fleets::ListFleetsInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::list_fleets::ListFleetsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_fleets::ListFleetsInput {
            build_id: self.build_id,
            script_id: self.script_id,
            limit: self.limit,
            next_token: self.next_token,
        })
    }
}
