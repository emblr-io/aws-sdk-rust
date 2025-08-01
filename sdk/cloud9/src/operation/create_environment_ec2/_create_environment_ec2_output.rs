// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateEnvironmentEc2Output {
    /// <p>The ID of the environment that was created.</p>
    pub environment_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateEnvironmentEc2Output {
    /// <p>The ID of the environment that was created.</p>
    pub fn environment_id(&self) -> ::std::option::Option<&str> {
        self.environment_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateEnvironmentEc2Output {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateEnvironmentEc2Output {
    /// Creates a new builder-style object to manufacture [`CreateEnvironmentEc2Output`](crate::operation::create_environment_ec2::CreateEnvironmentEc2Output).
    pub fn builder() -> crate::operation::create_environment_ec2::builders::CreateEnvironmentEc2OutputBuilder {
        crate::operation::create_environment_ec2::builders::CreateEnvironmentEc2OutputBuilder::default()
    }
}

/// A builder for [`CreateEnvironmentEc2Output`](crate::operation::create_environment_ec2::CreateEnvironmentEc2Output).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateEnvironmentEc2OutputBuilder {
    pub(crate) environment_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateEnvironmentEc2OutputBuilder {
    /// <p>The ID of the environment that was created.</p>
    pub fn environment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the environment that was created.</p>
    pub fn set_environment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_id = input;
        self
    }
    /// <p>The ID of the environment that was created.</p>
    pub fn get_environment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateEnvironmentEc2Output`](crate::operation::create_environment_ec2::CreateEnvironmentEc2Output).
    pub fn build(self) -> crate::operation::create_environment_ec2::CreateEnvironmentEc2Output {
        crate::operation::create_environment_ec2::CreateEnvironmentEc2Output {
            environment_id: self.environment_id,
            _request_id: self._request_id,
        }
    }
}
