// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteProvisioningTemplateVersionInput {
    /// <p>The name of the provisioning template version to delete.</p>
    pub template_name: ::std::option::Option<::std::string::String>,
    /// <p>The provisioning template version ID to delete.</p>
    pub version_id: ::std::option::Option<i32>,
}
impl DeleteProvisioningTemplateVersionInput {
    /// <p>The name of the provisioning template version to delete.</p>
    pub fn template_name(&self) -> ::std::option::Option<&str> {
        self.template_name.as_deref()
    }
    /// <p>The provisioning template version ID to delete.</p>
    pub fn version_id(&self) -> ::std::option::Option<i32> {
        self.version_id
    }
}
impl DeleteProvisioningTemplateVersionInput {
    /// Creates a new builder-style object to manufacture [`DeleteProvisioningTemplateVersionInput`](crate::operation::delete_provisioning_template_version::DeleteProvisioningTemplateVersionInput).
    pub fn builder() -> crate::operation::delete_provisioning_template_version::builders::DeleteProvisioningTemplateVersionInputBuilder {
        crate::operation::delete_provisioning_template_version::builders::DeleteProvisioningTemplateVersionInputBuilder::default()
    }
}

/// A builder for [`DeleteProvisioningTemplateVersionInput`](crate::operation::delete_provisioning_template_version::DeleteProvisioningTemplateVersionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteProvisioningTemplateVersionInputBuilder {
    pub(crate) template_name: ::std::option::Option<::std::string::String>,
    pub(crate) version_id: ::std::option::Option<i32>,
}
impl DeleteProvisioningTemplateVersionInputBuilder {
    /// <p>The name of the provisioning template version to delete.</p>
    /// This field is required.
    pub fn template_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the provisioning template version to delete.</p>
    pub fn set_template_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_name = input;
        self
    }
    /// <p>The name of the provisioning template version to delete.</p>
    pub fn get_template_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_name
    }
    /// <p>The provisioning template version ID to delete.</p>
    /// This field is required.
    pub fn version_id(mut self, input: i32) -> Self {
        self.version_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>The provisioning template version ID to delete.</p>
    pub fn set_version_id(mut self, input: ::std::option::Option<i32>) -> Self {
        self.version_id = input;
        self
    }
    /// <p>The provisioning template version ID to delete.</p>
    pub fn get_version_id(&self) -> &::std::option::Option<i32> {
        &self.version_id
    }
    /// Consumes the builder and constructs a [`DeleteProvisioningTemplateVersionInput`](crate::operation::delete_provisioning_template_version::DeleteProvisioningTemplateVersionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_provisioning_template_version::DeleteProvisioningTemplateVersionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::delete_provisioning_template_version::DeleteProvisioningTemplateVersionInput {
                template_name: self.template_name,
                version_id: self.version_id,
            },
        )
    }
}
