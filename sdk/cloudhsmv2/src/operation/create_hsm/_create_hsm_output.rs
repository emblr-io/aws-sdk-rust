// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateHsmOutput {
    /// <p>Information about the HSM that was created.</p>
    pub hsm: ::std::option::Option<crate::types::Hsm>,
    _request_id: Option<String>,
}
impl CreateHsmOutput {
    /// <p>Information about the HSM that was created.</p>
    pub fn hsm(&self) -> ::std::option::Option<&crate::types::Hsm> {
        self.hsm.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateHsmOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateHsmOutput {
    /// Creates a new builder-style object to manufacture [`CreateHsmOutput`](crate::operation::create_hsm::CreateHsmOutput).
    pub fn builder() -> crate::operation::create_hsm::builders::CreateHsmOutputBuilder {
        crate::operation::create_hsm::builders::CreateHsmOutputBuilder::default()
    }
}

/// A builder for [`CreateHsmOutput`](crate::operation::create_hsm::CreateHsmOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateHsmOutputBuilder {
    pub(crate) hsm: ::std::option::Option<crate::types::Hsm>,
    _request_id: Option<String>,
}
impl CreateHsmOutputBuilder {
    /// <p>Information about the HSM that was created.</p>
    pub fn hsm(mut self, input: crate::types::Hsm) -> Self {
        self.hsm = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the HSM that was created.</p>
    pub fn set_hsm(mut self, input: ::std::option::Option<crate::types::Hsm>) -> Self {
        self.hsm = input;
        self
    }
    /// <p>Information about the HSM that was created.</p>
    pub fn get_hsm(&self) -> &::std::option::Option<crate::types::Hsm> {
        &self.hsm
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateHsmOutput`](crate::operation::create_hsm::CreateHsmOutput).
    pub fn build(self) -> crate::operation::create_hsm::CreateHsmOutput {
        crate::operation::create_hsm::CreateHsmOutput {
            hsm: self.hsm,
            _request_id: self._request_id,
        }
    }
}
