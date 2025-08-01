// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The response parameters for CreateInstance.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateInstanceOutput {
    /// <p>The AWS Supply Chain instance resource data details.</p>
    pub instance: ::std::option::Option<crate::types::Instance>,
    _request_id: Option<String>,
}
impl CreateInstanceOutput {
    /// <p>The AWS Supply Chain instance resource data details.</p>
    pub fn instance(&self) -> ::std::option::Option<&crate::types::Instance> {
        self.instance.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateInstanceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateInstanceOutput {
    /// Creates a new builder-style object to manufacture [`CreateInstanceOutput`](crate::operation::create_instance::CreateInstanceOutput).
    pub fn builder() -> crate::operation::create_instance::builders::CreateInstanceOutputBuilder {
        crate::operation::create_instance::builders::CreateInstanceOutputBuilder::default()
    }
}

/// A builder for [`CreateInstanceOutput`](crate::operation::create_instance::CreateInstanceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateInstanceOutputBuilder {
    pub(crate) instance: ::std::option::Option<crate::types::Instance>,
    _request_id: Option<String>,
}
impl CreateInstanceOutputBuilder {
    /// <p>The AWS Supply Chain instance resource data details.</p>
    /// This field is required.
    pub fn instance(mut self, input: crate::types::Instance) -> Self {
        self.instance = ::std::option::Option::Some(input);
        self
    }
    /// <p>The AWS Supply Chain instance resource data details.</p>
    pub fn set_instance(mut self, input: ::std::option::Option<crate::types::Instance>) -> Self {
        self.instance = input;
        self
    }
    /// <p>The AWS Supply Chain instance resource data details.</p>
    pub fn get_instance(&self) -> &::std::option::Option<crate::types::Instance> {
        &self.instance
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateInstanceOutput`](crate::operation::create_instance::CreateInstanceOutput).
    pub fn build(self) -> crate::operation::create_instance::CreateInstanceOutput {
        crate::operation::create_instance::CreateInstanceOutput {
            instance: self.instance,
            _request_id: self._request_id,
        }
    }
}
