// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Structure describing a provisioning profile.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProvisioningProfileSummary {
    /// <p>The name of the provisioning template.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the provisioning profile.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the provisioning template used in the provisioning profile.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The type of provisioning workflow the device uses for onboarding to IoT managed integrations.</p>
    pub provisioning_type: ::std::option::Option<crate::types::ProvisioningType>,
}
impl ProvisioningProfileSummary {
    /// <p>The name of the provisioning template.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The identifier of the provisioning profile.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the provisioning template used in the provisioning profile.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The type of provisioning workflow the device uses for onboarding to IoT managed integrations.</p>
    pub fn provisioning_type(&self) -> ::std::option::Option<&crate::types::ProvisioningType> {
        self.provisioning_type.as_ref()
    }
}
impl ProvisioningProfileSummary {
    /// Creates a new builder-style object to manufacture [`ProvisioningProfileSummary`](crate::types::ProvisioningProfileSummary).
    pub fn builder() -> crate::types::builders::ProvisioningProfileSummaryBuilder {
        crate::types::builders::ProvisioningProfileSummaryBuilder::default()
    }
}

/// A builder for [`ProvisioningProfileSummary`](crate::types::ProvisioningProfileSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProvisioningProfileSummaryBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) provisioning_type: ::std::option::Option<crate::types::ProvisioningType>,
}
impl ProvisioningProfileSummaryBuilder {
    /// <p>The name of the provisioning template.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the provisioning template.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the provisioning template.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The identifier of the provisioning profile.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the provisioning profile.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the provisioning profile.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The Amazon Resource Name (ARN) of the provisioning template used in the provisioning profile.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the provisioning template used in the provisioning profile.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the provisioning template used in the provisioning profile.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The type of provisioning workflow the device uses for onboarding to IoT managed integrations.</p>
    pub fn provisioning_type(mut self, input: crate::types::ProvisioningType) -> Self {
        self.provisioning_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of provisioning workflow the device uses for onboarding to IoT managed integrations.</p>
    pub fn set_provisioning_type(mut self, input: ::std::option::Option<crate::types::ProvisioningType>) -> Self {
        self.provisioning_type = input;
        self
    }
    /// <p>The type of provisioning workflow the device uses for onboarding to IoT managed integrations.</p>
    pub fn get_provisioning_type(&self) -> &::std::option::Option<crate::types::ProvisioningType> {
        &self.provisioning_type
    }
    /// Consumes the builder and constructs a [`ProvisioningProfileSummary`](crate::types::ProvisioningProfileSummary).
    pub fn build(self) -> crate::types::ProvisioningProfileSummary {
        crate::types::ProvisioningProfileSummary {
            name: self.name,
            id: self.id,
            arn: self.arn,
            provisioning_type: self.provisioning_type,
        }
    }
}
