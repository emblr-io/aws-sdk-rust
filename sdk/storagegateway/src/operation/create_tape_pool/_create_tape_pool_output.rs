// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateTapePoolOutput {
    /// <p>The unique Amazon Resource Name (ARN) that represents the custom tape pool. Use the <code>ListTapePools</code> operation to return a list of tape pools for your account and Amazon Web Services Region.</p>
    pub pool_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateTapePoolOutput {
    /// <p>The unique Amazon Resource Name (ARN) that represents the custom tape pool. Use the <code>ListTapePools</code> operation to return a list of tape pools for your account and Amazon Web Services Region.</p>
    pub fn pool_arn(&self) -> ::std::option::Option<&str> {
        self.pool_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateTapePoolOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateTapePoolOutput {
    /// Creates a new builder-style object to manufacture [`CreateTapePoolOutput`](crate::operation::create_tape_pool::CreateTapePoolOutput).
    pub fn builder() -> crate::operation::create_tape_pool::builders::CreateTapePoolOutputBuilder {
        crate::operation::create_tape_pool::builders::CreateTapePoolOutputBuilder::default()
    }
}

/// A builder for [`CreateTapePoolOutput`](crate::operation::create_tape_pool::CreateTapePoolOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateTapePoolOutputBuilder {
    pub(crate) pool_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateTapePoolOutputBuilder {
    /// <p>The unique Amazon Resource Name (ARN) that represents the custom tape pool. Use the <code>ListTapePools</code> operation to return a list of tape pools for your account and Amazon Web Services Region.</p>
    pub fn pool_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pool_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique Amazon Resource Name (ARN) that represents the custom tape pool. Use the <code>ListTapePools</code> operation to return a list of tape pools for your account and Amazon Web Services Region.</p>
    pub fn set_pool_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pool_arn = input;
        self
    }
    /// <p>The unique Amazon Resource Name (ARN) that represents the custom tape pool. Use the <code>ListTapePools</code> operation to return a list of tape pools for your account and Amazon Web Services Region.</p>
    pub fn get_pool_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.pool_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateTapePoolOutput`](crate::operation::create_tape_pool::CreateTapePoolOutput).
    pub fn build(self) -> crate::operation::create_tape_pool::CreateTapePoolOutput {
        crate::operation::create_tape_pool::CreateTapePoolOutput {
            pool_arn: self.pool_arn,
            _request_id: self._request_id,
        }
    }
}
