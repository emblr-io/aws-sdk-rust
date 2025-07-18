// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A list of additional configurations which will be configured for the organization.</p>
/// <p>Additional configuration applies to only GuardDuty Runtime Monitoring protection plan.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OrganizationAdditionalConfiguration {
    /// <p>The name of the additional configuration that will be configured for the organization. These values are applicable to only Runtime Monitoring protection plan.</p>
    pub name: ::std::option::Option<crate::types::OrgFeatureAdditionalConfiguration>,
    /// <p>The status of the additional configuration that will be configured for the organization. Use one of the following values to configure the feature status for the entire organization:</p>
    /// <ul>
    /// <li>
    /// <p><code>NEW</code>: Indicates that when a new account joins the organization, they will have the additional configuration enabled automatically.</p></li>
    /// <li>
    /// <p><code>ALL</code>: Indicates that all accounts in the organization have the additional configuration enabled automatically. This includes <code>NEW</code> accounts that join the organization and accounts that may have been suspended or removed from the organization in GuardDuty.</p>
    /// <p>It may take up to 24 hours to update the configuration for all the member accounts.</p></li>
    /// <li>
    /// <p><code>NONE</code>: Indicates that the additional configuration will not be automatically enabled for any account in the organization. The administrator must manage the additional configuration for each account individually.</p></li>
    /// </ul>
    pub auto_enable: ::std::option::Option<crate::types::OrgFeatureStatus>,
}
impl OrganizationAdditionalConfiguration {
    /// <p>The name of the additional configuration that will be configured for the organization. These values are applicable to only Runtime Monitoring protection plan.</p>
    pub fn name(&self) -> ::std::option::Option<&crate::types::OrgFeatureAdditionalConfiguration> {
        self.name.as_ref()
    }
    /// <p>The status of the additional configuration that will be configured for the organization. Use one of the following values to configure the feature status for the entire organization:</p>
    /// <ul>
    /// <li>
    /// <p><code>NEW</code>: Indicates that when a new account joins the organization, they will have the additional configuration enabled automatically.</p></li>
    /// <li>
    /// <p><code>ALL</code>: Indicates that all accounts in the organization have the additional configuration enabled automatically. This includes <code>NEW</code> accounts that join the organization and accounts that may have been suspended or removed from the organization in GuardDuty.</p>
    /// <p>It may take up to 24 hours to update the configuration for all the member accounts.</p></li>
    /// <li>
    /// <p><code>NONE</code>: Indicates that the additional configuration will not be automatically enabled for any account in the organization. The administrator must manage the additional configuration for each account individually.</p></li>
    /// </ul>
    pub fn auto_enable(&self) -> ::std::option::Option<&crate::types::OrgFeatureStatus> {
        self.auto_enable.as_ref()
    }
}
impl OrganizationAdditionalConfiguration {
    /// Creates a new builder-style object to manufacture [`OrganizationAdditionalConfiguration`](crate::types::OrganizationAdditionalConfiguration).
    pub fn builder() -> crate::types::builders::OrganizationAdditionalConfigurationBuilder {
        crate::types::builders::OrganizationAdditionalConfigurationBuilder::default()
    }
}

/// A builder for [`OrganizationAdditionalConfiguration`](crate::types::OrganizationAdditionalConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OrganizationAdditionalConfigurationBuilder {
    pub(crate) name: ::std::option::Option<crate::types::OrgFeatureAdditionalConfiguration>,
    pub(crate) auto_enable: ::std::option::Option<crate::types::OrgFeatureStatus>,
}
impl OrganizationAdditionalConfigurationBuilder {
    /// <p>The name of the additional configuration that will be configured for the organization. These values are applicable to only Runtime Monitoring protection plan.</p>
    pub fn name(mut self, input: crate::types::OrgFeatureAdditionalConfiguration) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the additional configuration that will be configured for the organization. These values are applicable to only Runtime Monitoring protection plan.</p>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::OrgFeatureAdditionalConfiguration>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the additional configuration that will be configured for the organization. These values are applicable to only Runtime Monitoring protection plan.</p>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::OrgFeatureAdditionalConfiguration> {
        &self.name
    }
    /// <p>The status of the additional configuration that will be configured for the organization. Use one of the following values to configure the feature status for the entire organization:</p>
    /// <ul>
    /// <li>
    /// <p><code>NEW</code>: Indicates that when a new account joins the organization, they will have the additional configuration enabled automatically.</p></li>
    /// <li>
    /// <p><code>ALL</code>: Indicates that all accounts in the organization have the additional configuration enabled automatically. This includes <code>NEW</code> accounts that join the organization and accounts that may have been suspended or removed from the organization in GuardDuty.</p>
    /// <p>It may take up to 24 hours to update the configuration for all the member accounts.</p></li>
    /// <li>
    /// <p><code>NONE</code>: Indicates that the additional configuration will not be automatically enabled for any account in the organization. The administrator must manage the additional configuration for each account individually.</p></li>
    /// </ul>
    pub fn auto_enable(mut self, input: crate::types::OrgFeatureStatus) -> Self {
        self.auto_enable = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the additional configuration that will be configured for the organization. Use one of the following values to configure the feature status for the entire organization:</p>
    /// <ul>
    /// <li>
    /// <p><code>NEW</code>: Indicates that when a new account joins the organization, they will have the additional configuration enabled automatically.</p></li>
    /// <li>
    /// <p><code>ALL</code>: Indicates that all accounts in the organization have the additional configuration enabled automatically. This includes <code>NEW</code> accounts that join the organization and accounts that may have been suspended or removed from the organization in GuardDuty.</p>
    /// <p>It may take up to 24 hours to update the configuration for all the member accounts.</p></li>
    /// <li>
    /// <p><code>NONE</code>: Indicates that the additional configuration will not be automatically enabled for any account in the organization. The administrator must manage the additional configuration for each account individually.</p></li>
    /// </ul>
    pub fn set_auto_enable(mut self, input: ::std::option::Option<crate::types::OrgFeatureStatus>) -> Self {
        self.auto_enable = input;
        self
    }
    /// <p>The status of the additional configuration that will be configured for the organization. Use one of the following values to configure the feature status for the entire organization:</p>
    /// <ul>
    /// <li>
    /// <p><code>NEW</code>: Indicates that when a new account joins the organization, they will have the additional configuration enabled automatically.</p></li>
    /// <li>
    /// <p><code>ALL</code>: Indicates that all accounts in the organization have the additional configuration enabled automatically. This includes <code>NEW</code> accounts that join the organization and accounts that may have been suspended or removed from the organization in GuardDuty.</p>
    /// <p>It may take up to 24 hours to update the configuration for all the member accounts.</p></li>
    /// <li>
    /// <p><code>NONE</code>: Indicates that the additional configuration will not be automatically enabled for any account in the organization. The administrator must manage the additional configuration for each account individually.</p></li>
    /// </ul>
    pub fn get_auto_enable(&self) -> &::std::option::Option<crate::types::OrgFeatureStatus> {
        &self.auto_enable
    }
    /// Consumes the builder and constructs a [`OrganizationAdditionalConfiguration`](crate::types::OrganizationAdditionalConfiguration).
    pub fn build(self) -> crate::types::OrganizationAdditionalConfiguration {
        crate::types::OrganizationAdditionalConfiguration {
            name: self.name,
            auto_enable: self.auto_enable,
        }
    }
}
