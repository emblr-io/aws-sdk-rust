// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The parameters for encrypting content.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Encryption {
    /// <p>A 128-bit, 16-byte hex value represented by a 32-character string, used in conjunction with the key for encrypting content. If you don't specify a value, then MediaPackage creates the constant initialization vector (IV).</p>
    pub constant_initialization_vector: ::std::option::Option<::std::string::String>,
    /// <p>The encryption method to use.</p>
    pub encryption_method: ::std::option::Option<crate::types::EncryptionMethod>,
    /// <p>The frequency (in seconds) of key changes for live workflows, in which content is streamed real time. The service retrieves content keys before the live content begins streaming, and then retrieves them as needed over the lifetime of the workflow. By default, key rotation is set to 300 seconds (5 minutes), the minimum rotation interval, which is equivalent to setting it to 300. If you don't enter an interval, content keys aren't rotated.</p>
    /// <p>The following example setting causes the service to rotate keys every thirty minutes: <code>1800</code></p>
    pub key_rotation_interval_seconds: ::std::option::Option<i32>,
    /// <p>Excludes SEIG and SGPD boxes from segment metadata in CMAF containers.</p>
    /// <p>When set to <code>true</code>, MediaPackage omits these DRM metadata boxes from CMAF segments, which can improve compatibility with certain devices and players that don't support these boxes.</p>
    /// <p>Important considerations:</p>
    /// <ul>
    /// <li>
    /// <p>This setting only affects CMAF container formats</p></li>
    /// <li>
    /// <p>Key rotation can still be handled through media playlist signaling</p></li>
    /// <li>
    /// <p>PSSH and TENC boxes remain unaffected</p></li>
    /// <li>
    /// <p>Default behavior is preserved when this setting is disabled</p></li>
    /// </ul>
    /// <p>Valid values: <code>true</code> | <code>false</code></p>
    /// <p>Default: <code>false</code></p>
    pub cmaf_exclude_segment_drm_metadata: ::std::option::Option<bool>,
    /// <p>The parameters for the SPEKE key provider.</p>
    pub speke_key_provider: ::std::option::Option<crate::types::SpekeKeyProvider>,
}
impl Encryption {
    /// <p>A 128-bit, 16-byte hex value represented by a 32-character string, used in conjunction with the key for encrypting content. If you don't specify a value, then MediaPackage creates the constant initialization vector (IV).</p>
    pub fn constant_initialization_vector(&self) -> ::std::option::Option<&str> {
        self.constant_initialization_vector.as_deref()
    }
    /// <p>The encryption method to use.</p>
    pub fn encryption_method(&self) -> ::std::option::Option<&crate::types::EncryptionMethod> {
        self.encryption_method.as_ref()
    }
    /// <p>The frequency (in seconds) of key changes for live workflows, in which content is streamed real time. The service retrieves content keys before the live content begins streaming, and then retrieves them as needed over the lifetime of the workflow. By default, key rotation is set to 300 seconds (5 minutes), the minimum rotation interval, which is equivalent to setting it to 300. If you don't enter an interval, content keys aren't rotated.</p>
    /// <p>The following example setting causes the service to rotate keys every thirty minutes: <code>1800</code></p>
    pub fn key_rotation_interval_seconds(&self) -> ::std::option::Option<i32> {
        self.key_rotation_interval_seconds
    }
    /// <p>Excludes SEIG and SGPD boxes from segment metadata in CMAF containers.</p>
    /// <p>When set to <code>true</code>, MediaPackage omits these DRM metadata boxes from CMAF segments, which can improve compatibility with certain devices and players that don't support these boxes.</p>
    /// <p>Important considerations:</p>
    /// <ul>
    /// <li>
    /// <p>This setting only affects CMAF container formats</p></li>
    /// <li>
    /// <p>Key rotation can still be handled through media playlist signaling</p></li>
    /// <li>
    /// <p>PSSH and TENC boxes remain unaffected</p></li>
    /// <li>
    /// <p>Default behavior is preserved when this setting is disabled</p></li>
    /// </ul>
    /// <p>Valid values: <code>true</code> | <code>false</code></p>
    /// <p>Default: <code>false</code></p>
    pub fn cmaf_exclude_segment_drm_metadata(&self) -> ::std::option::Option<bool> {
        self.cmaf_exclude_segment_drm_metadata
    }
    /// <p>The parameters for the SPEKE key provider.</p>
    pub fn speke_key_provider(&self) -> ::std::option::Option<&crate::types::SpekeKeyProvider> {
        self.speke_key_provider.as_ref()
    }
}
impl Encryption {
    /// Creates a new builder-style object to manufacture [`Encryption`](crate::types::Encryption).
    pub fn builder() -> crate::types::builders::EncryptionBuilder {
        crate::types::builders::EncryptionBuilder::default()
    }
}

/// A builder for [`Encryption`](crate::types::Encryption).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EncryptionBuilder {
    pub(crate) constant_initialization_vector: ::std::option::Option<::std::string::String>,
    pub(crate) encryption_method: ::std::option::Option<crate::types::EncryptionMethod>,
    pub(crate) key_rotation_interval_seconds: ::std::option::Option<i32>,
    pub(crate) cmaf_exclude_segment_drm_metadata: ::std::option::Option<bool>,
    pub(crate) speke_key_provider: ::std::option::Option<crate::types::SpekeKeyProvider>,
}
impl EncryptionBuilder {
    /// <p>A 128-bit, 16-byte hex value represented by a 32-character string, used in conjunction with the key for encrypting content. If you don't specify a value, then MediaPackage creates the constant initialization vector (IV).</p>
    pub fn constant_initialization_vector(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.constant_initialization_vector = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A 128-bit, 16-byte hex value represented by a 32-character string, used in conjunction with the key for encrypting content. If you don't specify a value, then MediaPackage creates the constant initialization vector (IV).</p>
    pub fn set_constant_initialization_vector(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.constant_initialization_vector = input;
        self
    }
    /// <p>A 128-bit, 16-byte hex value represented by a 32-character string, used in conjunction with the key for encrypting content. If you don't specify a value, then MediaPackage creates the constant initialization vector (IV).</p>
    pub fn get_constant_initialization_vector(&self) -> &::std::option::Option<::std::string::String> {
        &self.constant_initialization_vector
    }
    /// <p>The encryption method to use.</p>
    /// This field is required.
    pub fn encryption_method(mut self, input: crate::types::EncryptionMethod) -> Self {
        self.encryption_method = ::std::option::Option::Some(input);
        self
    }
    /// <p>The encryption method to use.</p>
    pub fn set_encryption_method(mut self, input: ::std::option::Option<crate::types::EncryptionMethod>) -> Self {
        self.encryption_method = input;
        self
    }
    /// <p>The encryption method to use.</p>
    pub fn get_encryption_method(&self) -> &::std::option::Option<crate::types::EncryptionMethod> {
        &self.encryption_method
    }
    /// <p>The frequency (in seconds) of key changes for live workflows, in which content is streamed real time. The service retrieves content keys before the live content begins streaming, and then retrieves them as needed over the lifetime of the workflow. By default, key rotation is set to 300 seconds (5 minutes), the minimum rotation interval, which is equivalent to setting it to 300. If you don't enter an interval, content keys aren't rotated.</p>
    /// <p>The following example setting causes the service to rotate keys every thirty minutes: <code>1800</code></p>
    pub fn key_rotation_interval_seconds(mut self, input: i32) -> Self {
        self.key_rotation_interval_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The frequency (in seconds) of key changes for live workflows, in which content is streamed real time. The service retrieves content keys before the live content begins streaming, and then retrieves them as needed over the lifetime of the workflow. By default, key rotation is set to 300 seconds (5 minutes), the minimum rotation interval, which is equivalent to setting it to 300. If you don't enter an interval, content keys aren't rotated.</p>
    /// <p>The following example setting causes the service to rotate keys every thirty minutes: <code>1800</code></p>
    pub fn set_key_rotation_interval_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.key_rotation_interval_seconds = input;
        self
    }
    /// <p>The frequency (in seconds) of key changes for live workflows, in which content is streamed real time. The service retrieves content keys before the live content begins streaming, and then retrieves them as needed over the lifetime of the workflow. By default, key rotation is set to 300 seconds (5 minutes), the minimum rotation interval, which is equivalent to setting it to 300. If you don't enter an interval, content keys aren't rotated.</p>
    /// <p>The following example setting causes the service to rotate keys every thirty minutes: <code>1800</code></p>
    pub fn get_key_rotation_interval_seconds(&self) -> &::std::option::Option<i32> {
        &self.key_rotation_interval_seconds
    }
    /// <p>Excludes SEIG and SGPD boxes from segment metadata in CMAF containers.</p>
    /// <p>When set to <code>true</code>, MediaPackage omits these DRM metadata boxes from CMAF segments, which can improve compatibility with certain devices and players that don't support these boxes.</p>
    /// <p>Important considerations:</p>
    /// <ul>
    /// <li>
    /// <p>This setting only affects CMAF container formats</p></li>
    /// <li>
    /// <p>Key rotation can still be handled through media playlist signaling</p></li>
    /// <li>
    /// <p>PSSH and TENC boxes remain unaffected</p></li>
    /// <li>
    /// <p>Default behavior is preserved when this setting is disabled</p></li>
    /// </ul>
    /// <p>Valid values: <code>true</code> | <code>false</code></p>
    /// <p>Default: <code>false</code></p>
    pub fn cmaf_exclude_segment_drm_metadata(mut self, input: bool) -> Self {
        self.cmaf_exclude_segment_drm_metadata = ::std::option::Option::Some(input);
        self
    }
    /// <p>Excludes SEIG and SGPD boxes from segment metadata in CMAF containers.</p>
    /// <p>When set to <code>true</code>, MediaPackage omits these DRM metadata boxes from CMAF segments, which can improve compatibility with certain devices and players that don't support these boxes.</p>
    /// <p>Important considerations:</p>
    /// <ul>
    /// <li>
    /// <p>This setting only affects CMAF container formats</p></li>
    /// <li>
    /// <p>Key rotation can still be handled through media playlist signaling</p></li>
    /// <li>
    /// <p>PSSH and TENC boxes remain unaffected</p></li>
    /// <li>
    /// <p>Default behavior is preserved when this setting is disabled</p></li>
    /// </ul>
    /// <p>Valid values: <code>true</code> | <code>false</code></p>
    /// <p>Default: <code>false</code></p>
    pub fn set_cmaf_exclude_segment_drm_metadata(mut self, input: ::std::option::Option<bool>) -> Self {
        self.cmaf_exclude_segment_drm_metadata = input;
        self
    }
    /// <p>Excludes SEIG and SGPD boxes from segment metadata in CMAF containers.</p>
    /// <p>When set to <code>true</code>, MediaPackage omits these DRM metadata boxes from CMAF segments, which can improve compatibility with certain devices and players that don't support these boxes.</p>
    /// <p>Important considerations:</p>
    /// <ul>
    /// <li>
    /// <p>This setting only affects CMAF container formats</p></li>
    /// <li>
    /// <p>Key rotation can still be handled through media playlist signaling</p></li>
    /// <li>
    /// <p>PSSH and TENC boxes remain unaffected</p></li>
    /// <li>
    /// <p>Default behavior is preserved when this setting is disabled</p></li>
    /// </ul>
    /// <p>Valid values: <code>true</code> | <code>false</code></p>
    /// <p>Default: <code>false</code></p>
    pub fn get_cmaf_exclude_segment_drm_metadata(&self) -> &::std::option::Option<bool> {
        &self.cmaf_exclude_segment_drm_metadata
    }
    /// <p>The parameters for the SPEKE key provider.</p>
    /// This field is required.
    pub fn speke_key_provider(mut self, input: crate::types::SpekeKeyProvider) -> Self {
        self.speke_key_provider = ::std::option::Option::Some(input);
        self
    }
    /// <p>The parameters for the SPEKE key provider.</p>
    pub fn set_speke_key_provider(mut self, input: ::std::option::Option<crate::types::SpekeKeyProvider>) -> Self {
        self.speke_key_provider = input;
        self
    }
    /// <p>The parameters for the SPEKE key provider.</p>
    pub fn get_speke_key_provider(&self) -> &::std::option::Option<crate::types::SpekeKeyProvider> {
        &self.speke_key_provider
    }
    /// Consumes the builder and constructs a [`Encryption`](crate::types::Encryption).
    pub fn build(self) -> crate::types::Encryption {
        crate::types::Encryption {
            constant_initialization_vector: self.constant_initialization_vector,
            encryption_method: self.encryption_method,
            key_rotation_interval_seconds: self.key_rotation_interval_seconds,
            cmaf_exclude_segment_drm_metadata: self.cmaf_exclude_segment_drm_metadata,
            speke_key_provider: self.speke_key_provider,
        }
    }
}
