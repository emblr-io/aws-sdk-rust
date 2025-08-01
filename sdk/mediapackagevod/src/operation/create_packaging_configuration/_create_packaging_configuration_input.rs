// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// A new MediaPackage VOD PackagingConfiguration resource configuration.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreatePackagingConfigurationInput {
    /// A CMAF packaging configuration.
    pub cmaf_package: ::std::option::Option<crate::types::CmafPackage>,
    /// A Dynamic Adaptive Streaming over HTTP (DASH) packaging configuration.
    pub dash_package: ::std::option::Option<crate::types::DashPackage>,
    /// An HTTP Live Streaming (HLS) packaging configuration.
    pub hls_package: ::std::option::Option<crate::types::HlsPackage>,
    /// The ID of the PackagingConfiguration.
    pub id: ::std::option::Option<::std::string::String>,
    /// A Microsoft Smooth Streaming (MSS) PackagingConfiguration.
    pub mss_package: ::std::option::Option<crate::types::MssPackage>,
    /// The ID of a PackagingGroup.
    pub packaging_group_id: ::std::option::Option<::std::string::String>,
    /// A collection of tags associated with a resource
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreatePackagingConfigurationInput {
    /// A CMAF packaging configuration.
    pub fn cmaf_package(&self) -> ::std::option::Option<&crate::types::CmafPackage> {
        self.cmaf_package.as_ref()
    }
    /// A Dynamic Adaptive Streaming over HTTP (DASH) packaging configuration.
    pub fn dash_package(&self) -> ::std::option::Option<&crate::types::DashPackage> {
        self.dash_package.as_ref()
    }
    /// An HTTP Live Streaming (HLS) packaging configuration.
    pub fn hls_package(&self) -> ::std::option::Option<&crate::types::HlsPackage> {
        self.hls_package.as_ref()
    }
    /// The ID of the PackagingConfiguration.
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// A Microsoft Smooth Streaming (MSS) PackagingConfiguration.
    pub fn mss_package(&self) -> ::std::option::Option<&crate::types::MssPackage> {
        self.mss_package.as_ref()
    }
    /// The ID of a PackagingGroup.
    pub fn packaging_group_id(&self) -> ::std::option::Option<&str> {
        self.packaging_group_id.as_deref()
    }
    /// A collection of tags associated with a resource
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl CreatePackagingConfigurationInput {
    /// Creates a new builder-style object to manufacture [`CreatePackagingConfigurationInput`](crate::operation::create_packaging_configuration::CreatePackagingConfigurationInput).
    pub fn builder() -> crate::operation::create_packaging_configuration::builders::CreatePackagingConfigurationInputBuilder {
        crate::operation::create_packaging_configuration::builders::CreatePackagingConfigurationInputBuilder::default()
    }
}

/// A builder for [`CreatePackagingConfigurationInput`](crate::operation::create_packaging_configuration::CreatePackagingConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreatePackagingConfigurationInputBuilder {
    pub(crate) cmaf_package: ::std::option::Option<crate::types::CmafPackage>,
    pub(crate) dash_package: ::std::option::Option<crate::types::DashPackage>,
    pub(crate) hls_package: ::std::option::Option<crate::types::HlsPackage>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) mss_package: ::std::option::Option<crate::types::MssPackage>,
    pub(crate) packaging_group_id: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreatePackagingConfigurationInputBuilder {
    /// A CMAF packaging configuration.
    pub fn cmaf_package(mut self, input: crate::types::CmafPackage) -> Self {
        self.cmaf_package = ::std::option::Option::Some(input);
        self
    }
    /// A CMAF packaging configuration.
    pub fn set_cmaf_package(mut self, input: ::std::option::Option<crate::types::CmafPackage>) -> Self {
        self.cmaf_package = input;
        self
    }
    /// A CMAF packaging configuration.
    pub fn get_cmaf_package(&self) -> &::std::option::Option<crate::types::CmafPackage> {
        &self.cmaf_package
    }
    /// A Dynamic Adaptive Streaming over HTTP (DASH) packaging configuration.
    pub fn dash_package(mut self, input: crate::types::DashPackage) -> Self {
        self.dash_package = ::std::option::Option::Some(input);
        self
    }
    /// A Dynamic Adaptive Streaming over HTTP (DASH) packaging configuration.
    pub fn set_dash_package(mut self, input: ::std::option::Option<crate::types::DashPackage>) -> Self {
        self.dash_package = input;
        self
    }
    /// A Dynamic Adaptive Streaming over HTTP (DASH) packaging configuration.
    pub fn get_dash_package(&self) -> &::std::option::Option<crate::types::DashPackage> {
        &self.dash_package
    }
    /// An HTTP Live Streaming (HLS) packaging configuration.
    pub fn hls_package(mut self, input: crate::types::HlsPackage) -> Self {
        self.hls_package = ::std::option::Option::Some(input);
        self
    }
    /// An HTTP Live Streaming (HLS) packaging configuration.
    pub fn set_hls_package(mut self, input: ::std::option::Option<crate::types::HlsPackage>) -> Self {
        self.hls_package = input;
        self
    }
    /// An HTTP Live Streaming (HLS) packaging configuration.
    pub fn get_hls_package(&self) -> &::std::option::Option<crate::types::HlsPackage> {
        &self.hls_package
    }
    /// The ID of the PackagingConfiguration.
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// The ID of the PackagingConfiguration.
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// The ID of the PackagingConfiguration.
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// A Microsoft Smooth Streaming (MSS) PackagingConfiguration.
    pub fn mss_package(mut self, input: crate::types::MssPackage) -> Self {
        self.mss_package = ::std::option::Option::Some(input);
        self
    }
    /// A Microsoft Smooth Streaming (MSS) PackagingConfiguration.
    pub fn set_mss_package(mut self, input: ::std::option::Option<crate::types::MssPackage>) -> Self {
        self.mss_package = input;
        self
    }
    /// A Microsoft Smooth Streaming (MSS) PackagingConfiguration.
    pub fn get_mss_package(&self) -> &::std::option::Option<crate::types::MssPackage> {
        &self.mss_package
    }
    /// The ID of a PackagingGroup.
    /// This field is required.
    pub fn packaging_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.packaging_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// The ID of a PackagingGroup.
    pub fn set_packaging_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.packaging_group_id = input;
        self
    }
    /// The ID of a PackagingGroup.
    pub fn get_packaging_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.packaging_group_id
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// A collection of tags associated with a resource
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// A collection of tags associated with a resource
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// A collection of tags associated with a resource
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreatePackagingConfigurationInput`](crate::operation::create_packaging_configuration::CreatePackagingConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_packaging_configuration::CreatePackagingConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_packaging_configuration::CreatePackagingConfigurationInput {
            cmaf_package: self.cmaf_package,
            dash_package: self.dash_package,
            hls_package: self.hls_package,
            id: self.id,
            mss_package: self.mss_package,
            packaging_group_id: self.packaging_group_id,
            tags: self.tags,
        })
    }
}
