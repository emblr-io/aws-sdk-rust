// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateOrganizationalUnitOutput {
    /// <p>A structure that contains the details about the specified OU, including its new name.</p>
    pub organizational_unit: ::std::option::Option<crate::types::OrganizationalUnit>,
    _request_id: Option<String>,
}
impl UpdateOrganizationalUnitOutput {
    /// <p>A structure that contains the details about the specified OU, including its new name.</p>
    pub fn organizational_unit(&self) -> ::std::option::Option<&crate::types::OrganizationalUnit> {
        self.organizational_unit.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateOrganizationalUnitOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateOrganizationalUnitOutput {
    /// Creates a new builder-style object to manufacture [`UpdateOrganizationalUnitOutput`](crate::operation::update_organizational_unit::UpdateOrganizationalUnitOutput).
    pub fn builder() -> crate::operation::update_organizational_unit::builders::UpdateOrganizationalUnitOutputBuilder {
        crate::operation::update_organizational_unit::builders::UpdateOrganizationalUnitOutputBuilder::default()
    }
}

/// A builder for [`UpdateOrganizationalUnitOutput`](crate::operation::update_organizational_unit::UpdateOrganizationalUnitOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateOrganizationalUnitOutputBuilder {
    pub(crate) organizational_unit: ::std::option::Option<crate::types::OrganizationalUnit>,
    _request_id: Option<String>,
}
impl UpdateOrganizationalUnitOutputBuilder {
    /// <p>A structure that contains the details about the specified OU, including its new name.</p>
    pub fn organizational_unit(mut self, input: crate::types::OrganizationalUnit) -> Self {
        self.organizational_unit = ::std::option::Option::Some(input);
        self
    }
    /// <p>A structure that contains the details about the specified OU, including its new name.</p>
    pub fn set_organizational_unit(mut self, input: ::std::option::Option<crate::types::OrganizationalUnit>) -> Self {
        self.organizational_unit = input;
        self
    }
    /// <p>A structure that contains the details about the specified OU, including its new name.</p>
    pub fn get_organizational_unit(&self) -> &::std::option::Option<crate::types::OrganizationalUnit> {
        &self.organizational_unit
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateOrganizationalUnitOutput`](crate::operation::update_organizational_unit::UpdateOrganizationalUnitOutput).
    pub fn build(self) -> crate::operation::update_organizational_unit::UpdateOrganizationalUnitOutput {
        crate::operation::update_organizational_unit::UpdateOrganizationalUnitOutput {
            organizational_unit: self.organizational_unit,
            _request_id: self._request_id,
        }
    }
}
