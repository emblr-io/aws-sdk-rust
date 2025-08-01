// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TestTypeOutput {
    /// <p>The Amazon Resource Name (ARN) of the extension.</p>
    pub type_version_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl TestTypeOutput {
    /// <p>The Amazon Resource Name (ARN) of the extension.</p>
    pub fn type_version_arn(&self) -> ::std::option::Option<&str> {
        self.type_version_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for TestTypeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl TestTypeOutput {
    /// Creates a new builder-style object to manufacture [`TestTypeOutput`](crate::operation::test_type::TestTypeOutput).
    pub fn builder() -> crate::operation::test_type::builders::TestTypeOutputBuilder {
        crate::operation::test_type::builders::TestTypeOutputBuilder::default()
    }
}

/// A builder for [`TestTypeOutput`](crate::operation::test_type::TestTypeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TestTypeOutputBuilder {
    pub(crate) type_version_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl TestTypeOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the extension.</p>
    pub fn type_version_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.type_version_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the extension.</p>
    pub fn set_type_version_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.type_version_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the extension.</p>
    pub fn get_type_version_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.type_version_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`TestTypeOutput`](crate::operation::test_type::TestTypeOutput).
    pub fn build(self) -> crate::operation::test_type::TestTypeOutput {
        crate::operation::test_type::TestTypeOutput {
            type_version_arn: self.type_version_arn,
            _request_id: self._request_id,
        }
    }
}
