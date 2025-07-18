// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeOrganizationalUnitOutput {
    /// <p>A structure that contains details about the specified OU.</p>
    pub organizational_unit: ::std::option::Option<crate::types::OrganizationalUnit>,
    _request_id: Option<String>,
}
impl DescribeOrganizationalUnitOutput {
    /// <p>A structure that contains details about the specified OU.</p>
    pub fn organizational_unit(&self) -> ::std::option::Option<&crate::types::OrganizationalUnit> {
        self.organizational_unit.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeOrganizationalUnitOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeOrganizationalUnitOutput {
    /// Creates a new builder-style object to manufacture [`DescribeOrganizationalUnitOutput`](crate::operation::describe_organizational_unit::DescribeOrganizationalUnitOutput).
    pub fn builder() -> crate::operation::describe_organizational_unit::builders::DescribeOrganizationalUnitOutputBuilder {
        crate::operation::describe_organizational_unit::builders::DescribeOrganizationalUnitOutputBuilder::default()
    }
}

/// A builder for [`DescribeOrganizationalUnitOutput`](crate::operation::describe_organizational_unit::DescribeOrganizationalUnitOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeOrganizationalUnitOutputBuilder {
    pub(crate) organizational_unit: ::std::option::Option<crate::types::OrganizationalUnit>,
    _request_id: Option<String>,
}
impl DescribeOrganizationalUnitOutputBuilder {
    /// <p>A structure that contains details about the specified OU.</p>
    pub fn organizational_unit(mut self, input: crate::types::OrganizationalUnit) -> Self {
        self.organizational_unit = ::std::option::Option::Some(input);
        self
    }
    /// <p>A structure that contains details about the specified OU.</p>
    pub fn set_organizational_unit(mut self, input: ::std::option::Option<crate::types::OrganizationalUnit>) -> Self {
        self.organizational_unit = input;
        self
    }
    /// <p>A structure that contains details about the specified OU.</p>
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
    /// Consumes the builder and constructs a [`DescribeOrganizationalUnitOutput`](crate::operation::describe_organizational_unit::DescribeOrganizationalUnitOutput).
    pub fn build(self) -> crate::operation::describe_organizational_unit::DescribeOrganizationalUnitOutput {
        crate::operation::describe_organizational_unit::DescribeOrganizationalUnitOutput {
            organizational_unit: self.organizational_unit,
            _request_id: self._request_id,
        }
    }
}
