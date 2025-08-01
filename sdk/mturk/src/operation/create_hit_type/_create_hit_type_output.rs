// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateHitTypeOutput {
    /// <p>The ID of the newly registered HIT type.</p>
    pub hit_type_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateHitTypeOutput {
    /// <p>The ID of the newly registered HIT type.</p>
    pub fn hit_type_id(&self) -> ::std::option::Option<&str> {
        self.hit_type_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateHitTypeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateHitTypeOutput {
    /// Creates a new builder-style object to manufacture [`CreateHitTypeOutput`](crate::operation::create_hit_type::CreateHitTypeOutput).
    pub fn builder() -> crate::operation::create_hit_type::builders::CreateHitTypeOutputBuilder {
        crate::operation::create_hit_type::builders::CreateHitTypeOutputBuilder::default()
    }
}

/// A builder for [`CreateHitTypeOutput`](crate::operation::create_hit_type::CreateHitTypeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateHitTypeOutputBuilder {
    pub(crate) hit_type_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateHitTypeOutputBuilder {
    /// <p>The ID of the newly registered HIT type.</p>
    pub fn hit_type_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hit_type_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the newly registered HIT type.</p>
    pub fn set_hit_type_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hit_type_id = input;
        self
    }
    /// <p>The ID of the newly registered HIT type.</p>
    pub fn get_hit_type_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.hit_type_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateHitTypeOutput`](crate::operation::create_hit_type::CreateHitTypeOutput).
    pub fn build(self) -> crate::operation::create_hit_type::CreateHitTypeOutput {
        crate::operation::create_hit_type::CreateHitTypeOutput {
            hit_type_id: self.hit_type_id,
            _request_id: self._request_id,
        }
    }
}
