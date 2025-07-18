// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteOrganizationConformancePackInput {
    /// <p>The name of organization conformance pack that you want to delete.</p>
    pub organization_conformance_pack_name: ::std::option::Option<::std::string::String>,
}
impl DeleteOrganizationConformancePackInput {
    /// <p>The name of organization conformance pack that you want to delete.</p>
    pub fn organization_conformance_pack_name(&self) -> ::std::option::Option<&str> {
        self.organization_conformance_pack_name.as_deref()
    }
}
impl DeleteOrganizationConformancePackInput {
    /// Creates a new builder-style object to manufacture [`DeleteOrganizationConformancePackInput`](crate::operation::delete_organization_conformance_pack::DeleteOrganizationConformancePackInput).
    pub fn builder() -> crate::operation::delete_organization_conformance_pack::builders::DeleteOrganizationConformancePackInputBuilder {
        crate::operation::delete_organization_conformance_pack::builders::DeleteOrganizationConformancePackInputBuilder::default()
    }
}

/// A builder for [`DeleteOrganizationConformancePackInput`](crate::operation::delete_organization_conformance_pack::DeleteOrganizationConformancePackInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteOrganizationConformancePackInputBuilder {
    pub(crate) organization_conformance_pack_name: ::std::option::Option<::std::string::String>,
}
impl DeleteOrganizationConformancePackInputBuilder {
    /// <p>The name of organization conformance pack that you want to delete.</p>
    /// This field is required.
    pub fn organization_conformance_pack_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.organization_conformance_pack_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of organization conformance pack that you want to delete.</p>
    pub fn set_organization_conformance_pack_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.organization_conformance_pack_name = input;
        self
    }
    /// <p>The name of organization conformance pack that you want to delete.</p>
    pub fn get_organization_conformance_pack_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.organization_conformance_pack_name
    }
    /// Consumes the builder and constructs a [`DeleteOrganizationConformancePackInput`](crate::operation::delete_organization_conformance_pack::DeleteOrganizationConformancePackInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_organization_conformance_pack::DeleteOrganizationConformancePackInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::delete_organization_conformance_pack::DeleteOrganizationConformancePackInput {
                organization_conformance_pack_name: self.organization_conformance_pack_name,
            },
        )
    }
}
