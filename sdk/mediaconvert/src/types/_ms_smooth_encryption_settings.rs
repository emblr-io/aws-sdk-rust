// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// If you are using DRM, set DRM System to specify the value SpekeKeyProvider.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MsSmoothEncryptionSettings {
    /// If your output group type is HLS, DASH, or Microsoft Smooth, use these settings when doing DRM encryption with a SPEKE-compliant key provider. If your output group type is CMAF, use the SpekeKeyProviderCmaf settings instead.
    pub speke_key_provider: ::std::option::Option<crate::types::SpekeKeyProvider>,
}
impl MsSmoothEncryptionSettings {
    /// If your output group type is HLS, DASH, or Microsoft Smooth, use these settings when doing DRM encryption with a SPEKE-compliant key provider. If your output group type is CMAF, use the SpekeKeyProviderCmaf settings instead.
    pub fn speke_key_provider(&self) -> ::std::option::Option<&crate::types::SpekeKeyProvider> {
        self.speke_key_provider.as_ref()
    }
}
impl MsSmoothEncryptionSettings {
    /// Creates a new builder-style object to manufacture [`MsSmoothEncryptionSettings`](crate::types::MsSmoothEncryptionSettings).
    pub fn builder() -> crate::types::builders::MsSmoothEncryptionSettingsBuilder {
        crate::types::builders::MsSmoothEncryptionSettingsBuilder::default()
    }
}

/// A builder for [`MsSmoothEncryptionSettings`](crate::types::MsSmoothEncryptionSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MsSmoothEncryptionSettingsBuilder {
    pub(crate) speke_key_provider: ::std::option::Option<crate::types::SpekeKeyProvider>,
}
impl MsSmoothEncryptionSettingsBuilder {
    /// If your output group type is HLS, DASH, or Microsoft Smooth, use these settings when doing DRM encryption with a SPEKE-compliant key provider. If your output group type is CMAF, use the SpekeKeyProviderCmaf settings instead.
    pub fn speke_key_provider(mut self, input: crate::types::SpekeKeyProvider) -> Self {
        self.speke_key_provider = ::std::option::Option::Some(input);
        self
    }
    /// If your output group type is HLS, DASH, or Microsoft Smooth, use these settings when doing DRM encryption with a SPEKE-compliant key provider. If your output group type is CMAF, use the SpekeKeyProviderCmaf settings instead.
    pub fn set_speke_key_provider(mut self, input: ::std::option::Option<crate::types::SpekeKeyProvider>) -> Self {
        self.speke_key_provider = input;
        self
    }
    /// If your output group type is HLS, DASH, or Microsoft Smooth, use these settings when doing DRM encryption with a SPEKE-compliant key provider. If your output group type is CMAF, use the SpekeKeyProviderCmaf settings instead.
    pub fn get_speke_key_provider(&self) -> &::std::option::Option<crate::types::SpekeKeyProvider> {
        &self.speke_key_provider
    }
    /// Consumes the builder and constructs a [`MsSmoothEncryptionSettings`](crate::types::MsSmoothEncryptionSettings).
    pub fn build(self) -> crate::types::MsSmoothEncryptionSettings {
        crate::types::MsSmoothEncryptionSettings {
            speke_key_provider: self.speke_key_provider,
        }
    }
}
