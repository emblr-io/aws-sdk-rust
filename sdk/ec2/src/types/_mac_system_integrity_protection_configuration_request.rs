// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a custom configuration for a System Integrity Protection (SIP) modification task.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MacSystemIntegrityProtectionConfigurationRequest {
    /// <p>Enables or disables Apple Internal.</p>
    pub apple_internal: ::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus>,
    /// <p>Enables or disables Base System.</p>
    pub base_system: ::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus>,
    /// <p>Enables or disables Debugging Restrictions.</p>
    pub debugging_restrictions: ::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus>,
    /// <p>Enables or disables Dtrace Restrictions.</p>
    pub d_trace_restrictions: ::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus>,
    /// <p>Enables or disables Filesystem Protections.</p>
    pub filesystem_protections: ::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus>,
    /// <p>Enables or disables Kext Signing.</p>
    pub kext_signing: ::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus>,
    /// <p>Enables or disables Nvram Protections.</p>
    pub nvram_protections: ::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus>,
}
impl MacSystemIntegrityProtectionConfigurationRequest {
    /// <p>Enables or disables Apple Internal.</p>
    pub fn apple_internal(&self) -> ::std::option::Option<&crate::types::MacSystemIntegrityProtectionSettingStatus> {
        self.apple_internal.as_ref()
    }
    /// <p>Enables or disables Base System.</p>
    pub fn base_system(&self) -> ::std::option::Option<&crate::types::MacSystemIntegrityProtectionSettingStatus> {
        self.base_system.as_ref()
    }
    /// <p>Enables or disables Debugging Restrictions.</p>
    pub fn debugging_restrictions(&self) -> ::std::option::Option<&crate::types::MacSystemIntegrityProtectionSettingStatus> {
        self.debugging_restrictions.as_ref()
    }
    /// <p>Enables or disables Dtrace Restrictions.</p>
    pub fn d_trace_restrictions(&self) -> ::std::option::Option<&crate::types::MacSystemIntegrityProtectionSettingStatus> {
        self.d_trace_restrictions.as_ref()
    }
    /// <p>Enables or disables Filesystem Protections.</p>
    pub fn filesystem_protections(&self) -> ::std::option::Option<&crate::types::MacSystemIntegrityProtectionSettingStatus> {
        self.filesystem_protections.as_ref()
    }
    /// <p>Enables or disables Kext Signing.</p>
    pub fn kext_signing(&self) -> ::std::option::Option<&crate::types::MacSystemIntegrityProtectionSettingStatus> {
        self.kext_signing.as_ref()
    }
    /// <p>Enables or disables Nvram Protections.</p>
    pub fn nvram_protections(&self) -> ::std::option::Option<&crate::types::MacSystemIntegrityProtectionSettingStatus> {
        self.nvram_protections.as_ref()
    }
}
impl MacSystemIntegrityProtectionConfigurationRequest {
    /// Creates a new builder-style object to manufacture [`MacSystemIntegrityProtectionConfigurationRequest`](crate::types::MacSystemIntegrityProtectionConfigurationRequest).
    pub fn builder() -> crate::types::builders::MacSystemIntegrityProtectionConfigurationRequestBuilder {
        crate::types::builders::MacSystemIntegrityProtectionConfigurationRequestBuilder::default()
    }
}

/// A builder for [`MacSystemIntegrityProtectionConfigurationRequest`](crate::types::MacSystemIntegrityProtectionConfigurationRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MacSystemIntegrityProtectionConfigurationRequestBuilder {
    pub(crate) apple_internal: ::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus>,
    pub(crate) base_system: ::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus>,
    pub(crate) debugging_restrictions: ::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus>,
    pub(crate) d_trace_restrictions: ::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus>,
    pub(crate) filesystem_protections: ::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus>,
    pub(crate) kext_signing: ::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus>,
    pub(crate) nvram_protections: ::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus>,
}
impl MacSystemIntegrityProtectionConfigurationRequestBuilder {
    /// <p>Enables or disables Apple Internal.</p>
    pub fn apple_internal(mut self, input: crate::types::MacSystemIntegrityProtectionSettingStatus) -> Self {
        self.apple_internal = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables or disables Apple Internal.</p>
    pub fn set_apple_internal(mut self, input: ::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus>) -> Self {
        self.apple_internal = input;
        self
    }
    /// <p>Enables or disables Apple Internal.</p>
    pub fn get_apple_internal(&self) -> &::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus> {
        &self.apple_internal
    }
    /// <p>Enables or disables Base System.</p>
    pub fn base_system(mut self, input: crate::types::MacSystemIntegrityProtectionSettingStatus) -> Self {
        self.base_system = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables or disables Base System.</p>
    pub fn set_base_system(mut self, input: ::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus>) -> Self {
        self.base_system = input;
        self
    }
    /// <p>Enables or disables Base System.</p>
    pub fn get_base_system(&self) -> &::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus> {
        &self.base_system
    }
    /// <p>Enables or disables Debugging Restrictions.</p>
    pub fn debugging_restrictions(mut self, input: crate::types::MacSystemIntegrityProtectionSettingStatus) -> Self {
        self.debugging_restrictions = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables or disables Debugging Restrictions.</p>
    pub fn set_debugging_restrictions(mut self, input: ::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus>) -> Self {
        self.debugging_restrictions = input;
        self
    }
    /// <p>Enables or disables Debugging Restrictions.</p>
    pub fn get_debugging_restrictions(&self) -> &::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus> {
        &self.debugging_restrictions
    }
    /// <p>Enables or disables Dtrace Restrictions.</p>
    pub fn d_trace_restrictions(mut self, input: crate::types::MacSystemIntegrityProtectionSettingStatus) -> Self {
        self.d_trace_restrictions = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables or disables Dtrace Restrictions.</p>
    pub fn set_d_trace_restrictions(mut self, input: ::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus>) -> Self {
        self.d_trace_restrictions = input;
        self
    }
    /// <p>Enables or disables Dtrace Restrictions.</p>
    pub fn get_d_trace_restrictions(&self) -> &::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus> {
        &self.d_trace_restrictions
    }
    /// <p>Enables or disables Filesystem Protections.</p>
    pub fn filesystem_protections(mut self, input: crate::types::MacSystemIntegrityProtectionSettingStatus) -> Self {
        self.filesystem_protections = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables or disables Filesystem Protections.</p>
    pub fn set_filesystem_protections(mut self, input: ::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus>) -> Self {
        self.filesystem_protections = input;
        self
    }
    /// <p>Enables or disables Filesystem Protections.</p>
    pub fn get_filesystem_protections(&self) -> &::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus> {
        &self.filesystem_protections
    }
    /// <p>Enables or disables Kext Signing.</p>
    pub fn kext_signing(mut self, input: crate::types::MacSystemIntegrityProtectionSettingStatus) -> Self {
        self.kext_signing = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables or disables Kext Signing.</p>
    pub fn set_kext_signing(mut self, input: ::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus>) -> Self {
        self.kext_signing = input;
        self
    }
    /// <p>Enables or disables Kext Signing.</p>
    pub fn get_kext_signing(&self) -> &::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus> {
        &self.kext_signing
    }
    /// <p>Enables or disables Nvram Protections.</p>
    pub fn nvram_protections(mut self, input: crate::types::MacSystemIntegrityProtectionSettingStatus) -> Self {
        self.nvram_protections = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables or disables Nvram Protections.</p>
    pub fn set_nvram_protections(mut self, input: ::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus>) -> Self {
        self.nvram_protections = input;
        self
    }
    /// <p>Enables or disables Nvram Protections.</p>
    pub fn get_nvram_protections(&self) -> &::std::option::Option<crate::types::MacSystemIntegrityProtectionSettingStatus> {
        &self.nvram_protections
    }
    /// Consumes the builder and constructs a [`MacSystemIntegrityProtectionConfigurationRequest`](crate::types::MacSystemIntegrityProtectionConfigurationRequest).
    pub fn build(self) -> crate::types::MacSystemIntegrityProtectionConfigurationRequest {
        crate::types::MacSystemIntegrityProtectionConfigurationRequest {
            apple_internal: self.apple_internal,
            base_system: self.base_system,
            debugging_restrictions: self.debugging_restrictions,
            d_trace_restrictions: self.d_trace_restrictions,
            filesystem_protections: self.filesystem_protections,
            kext_signing: self.kext_signing,
            nvram_protections: self.nvram_protections,
        }
    }
}
