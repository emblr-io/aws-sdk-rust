// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// A Microsoft Smooth Streaming (MSS) PackagingConfiguration.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MssPackage {
    /// A Microsoft Smooth Streaming (MSS) encryption configuration.
    pub encryption: ::std::option::Option<crate::types::MssEncryption>,
    /// A list of MSS manifest configurations.
    pub mss_manifests: ::std::option::Option<::std::vec::Vec<crate::types::MssManifest>>,
    /// The duration (in seconds) of each segment.
    pub segment_duration_seconds: ::std::option::Option<i32>,
}
impl MssPackage {
    /// A Microsoft Smooth Streaming (MSS) encryption configuration.
    pub fn encryption(&self) -> ::std::option::Option<&crate::types::MssEncryption> {
        self.encryption.as_ref()
    }
    /// A list of MSS manifest configurations.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.mss_manifests.is_none()`.
    pub fn mss_manifests(&self) -> &[crate::types::MssManifest] {
        self.mss_manifests.as_deref().unwrap_or_default()
    }
    /// The duration (in seconds) of each segment.
    pub fn segment_duration_seconds(&self) -> ::std::option::Option<i32> {
        self.segment_duration_seconds
    }
}
impl MssPackage {
    /// Creates a new builder-style object to manufacture [`MssPackage`](crate::types::MssPackage).
    pub fn builder() -> crate::types::builders::MssPackageBuilder {
        crate::types::builders::MssPackageBuilder::default()
    }
}

/// A builder for [`MssPackage`](crate::types::MssPackage).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MssPackageBuilder {
    pub(crate) encryption: ::std::option::Option<crate::types::MssEncryption>,
    pub(crate) mss_manifests: ::std::option::Option<::std::vec::Vec<crate::types::MssManifest>>,
    pub(crate) segment_duration_seconds: ::std::option::Option<i32>,
}
impl MssPackageBuilder {
    /// A Microsoft Smooth Streaming (MSS) encryption configuration.
    pub fn encryption(mut self, input: crate::types::MssEncryption) -> Self {
        self.encryption = ::std::option::Option::Some(input);
        self
    }
    /// A Microsoft Smooth Streaming (MSS) encryption configuration.
    pub fn set_encryption(mut self, input: ::std::option::Option<crate::types::MssEncryption>) -> Self {
        self.encryption = input;
        self
    }
    /// A Microsoft Smooth Streaming (MSS) encryption configuration.
    pub fn get_encryption(&self) -> &::std::option::Option<crate::types::MssEncryption> {
        &self.encryption
    }
    /// Appends an item to `mss_manifests`.
    ///
    /// To override the contents of this collection use [`set_mss_manifests`](Self::set_mss_manifests).
    ///
    /// A list of MSS manifest configurations.
    pub fn mss_manifests(mut self, input: crate::types::MssManifest) -> Self {
        let mut v = self.mss_manifests.unwrap_or_default();
        v.push(input);
        self.mss_manifests = ::std::option::Option::Some(v);
        self
    }
    /// A list of MSS manifest configurations.
    pub fn set_mss_manifests(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MssManifest>>) -> Self {
        self.mss_manifests = input;
        self
    }
    /// A list of MSS manifest configurations.
    pub fn get_mss_manifests(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MssManifest>> {
        &self.mss_manifests
    }
    /// The duration (in seconds) of each segment.
    pub fn segment_duration_seconds(mut self, input: i32) -> Self {
        self.segment_duration_seconds = ::std::option::Option::Some(input);
        self
    }
    /// The duration (in seconds) of each segment.
    pub fn set_segment_duration_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.segment_duration_seconds = input;
        self
    }
    /// The duration (in seconds) of each segment.
    pub fn get_segment_duration_seconds(&self) -> &::std::option::Option<i32> {
        &self.segment_duration_seconds
    }
    /// Consumes the builder and constructs a [`MssPackage`](crate::types::MssPackage).
    pub fn build(self) -> crate::types::MssPackage {
        crate::types::MssPackage {
            encryption: self.encryption,
            mss_manifests: self.mss_manifests,
            segment_duration_seconds: self.segment_duration_seconds,
        }
    }
}
