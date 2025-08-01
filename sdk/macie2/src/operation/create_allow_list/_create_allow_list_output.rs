// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateAllowListOutput {
    /// <p>The Amazon Resource Name (ARN) of the allow list.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier for the allow list.</p>
    pub id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateAllowListOutput {
    /// <p>The Amazon Resource Name (ARN) of the allow list.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The unique identifier for the allow list.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateAllowListOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateAllowListOutput {
    /// Creates a new builder-style object to manufacture [`CreateAllowListOutput`](crate::operation::create_allow_list::CreateAllowListOutput).
    pub fn builder() -> crate::operation::create_allow_list::builders::CreateAllowListOutputBuilder {
        crate::operation::create_allow_list::builders::CreateAllowListOutputBuilder::default()
    }
}

/// A builder for [`CreateAllowListOutput`](crate::operation::create_allow_list::CreateAllowListOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateAllowListOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateAllowListOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the allow list.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the allow list.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the allow list.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The unique identifier for the allow list.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the allow list.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier for the allow list.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateAllowListOutput`](crate::operation::create_allow_list::CreateAllowListOutput).
    pub fn build(self) -> crate::operation::create_allow_list::CreateAllowListOutput {
        crate::operation::create_allow_list::CreateAllowListOutput {
            arn: self.arn,
            id: self.id,
            _request_id: self._request_id,
        }
    }
}
