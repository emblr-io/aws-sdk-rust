// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateOriginEndpointOutput {
    /// The Amazon Resource Name (ARN) assigned to the OriginEndpoint.
    pub arn: ::std::option::Option<::std::string::String>,
    /// CDN Authorization credentials
    pub authorization: ::std::option::Option<crate::types::Authorization>,
    /// The ID of the Channel the OriginEndpoint is associated with.
    pub channel_id: ::std::option::Option<::std::string::String>,
    /// A Common Media Application Format (CMAF) packaging configuration.
    pub cmaf_package: ::std::option::Option<crate::types::CmafPackage>,
    /// The date and time the OriginEndpoint was created.
    pub created_at: ::std::option::Option<::std::string::String>,
    /// A Dynamic Adaptive Streaming over HTTP (DASH) packaging configuration.
    pub dash_package: ::std::option::Option<crate::types::DashPackage>,
    /// A short text description of the OriginEndpoint.
    pub description: ::std::option::Option<::std::string::String>,
    /// An HTTP Live Streaming (HLS) packaging configuration.
    pub hls_package: ::std::option::Option<crate::types::HlsPackage>,
    /// The ID of the OriginEndpoint.
    pub id: ::std::option::Option<::std::string::String>,
    /// A short string appended to the end of the OriginEndpoint URL.
    pub manifest_name: ::std::option::Option<::std::string::String>,
    /// A Microsoft Smooth Streaming (MSS) packaging configuration.
    pub mss_package: ::std::option::Option<crate::types::MssPackage>,
    /// Control whether origination of video is allowed for this OriginEndpoint. If set to ALLOW, the OriginEndpoint may by requested, pursuant to any other form of access control. If set to DENY, the OriginEndpoint may not be requested. This can be helpful for Live to VOD harvesting, or for temporarily disabling origination
    pub origination: ::std::option::Option<crate::types::Origination>,
    /// Maximum duration (seconds) of content to retain for startover playback. If not specified, startover playback will be disabled for the OriginEndpoint.
    pub startover_window_seconds: ::std::option::Option<i32>,
    /// A collection of tags associated with a resource
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// Amount of delay (seconds) to enforce on the playback of live content. If not specified, there will be no time delay in effect for the OriginEndpoint.
    pub time_delay_seconds: ::std::option::Option<i32>,
    /// The URL of the packaged OriginEndpoint for consumption.
    pub url: ::std::option::Option<::std::string::String>,
    /// A list of source IP CIDR blocks that will be allowed to access the OriginEndpoint.
    pub whitelist: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl UpdateOriginEndpointOutput {
    /// The Amazon Resource Name (ARN) assigned to the OriginEndpoint.
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// CDN Authorization credentials
    pub fn authorization(&self) -> ::std::option::Option<&crate::types::Authorization> {
        self.authorization.as_ref()
    }
    /// The ID of the Channel the OriginEndpoint is associated with.
    pub fn channel_id(&self) -> ::std::option::Option<&str> {
        self.channel_id.as_deref()
    }
    /// A Common Media Application Format (CMAF) packaging configuration.
    pub fn cmaf_package(&self) -> ::std::option::Option<&crate::types::CmafPackage> {
        self.cmaf_package.as_ref()
    }
    /// The date and time the OriginEndpoint was created.
    pub fn created_at(&self) -> ::std::option::Option<&str> {
        self.created_at.as_deref()
    }
    /// A Dynamic Adaptive Streaming over HTTP (DASH) packaging configuration.
    pub fn dash_package(&self) -> ::std::option::Option<&crate::types::DashPackage> {
        self.dash_package.as_ref()
    }
    /// A short text description of the OriginEndpoint.
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// An HTTP Live Streaming (HLS) packaging configuration.
    pub fn hls_package(&self) -> ::std::option::Option<&crate::types::HlsPackage> {
        self.hls_package.as_ref()
    }
    /// The ID of the OriginEndpoint.
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// A short string appended to the end of the OriginEndpoint URL.
    pub fn manifest_name(&self) -> ::std::option::Option<&str> {
        self.manifest_name.as_deref()
    }
    /// A Microsoft Smooth Streaming (MSS) packaging configuration.
    pub fn mss_package(&self) -> ::std::option::Option<&crate::types::MssPackage> {
        self.mss_package.as_ref()
    }
    /// Control whether origination of video is allowed for this OriginEndpoint. If set to ALLOW, the OriginEndpoint may by requested, pursuant to any other form of access control. If set to DENY, the OriginEndpoint may not be requested. This can be helpful for Live to VOD harvesting, or for temporarily disabling origination
    pub fn origination(&self) -> ::std::option::Option<&crate::types::Origination> {
        self.origination.as_ref()
    }
    /// Maximum duration (seconds) of content to retain for startover playback. If not specified, startover playback will be disabled for the OriginEndpoint.
    pub fn startover_window_seconds(&self) -> ::std::option::Option<i32> {
        self.startover_window_seconds
    }
    /// A collection of tags associated with a resource
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// Amount of delay (seconds) to enforce on the playback of live content. If not specified, there will be no time delay in effect for the OriginEndpoint.
    pub fn time_delay_seconds(&self) -> ::std::option::Option<i32> {
        self.time_delay_seconds
    }
    /// The URL of the packaged OriginEndpoint for consumption.
    pub fn url(&self) -> ::std::option::Option<&str> {
        self.url.as_deref()
    }
    /// A list of source IP CIDR blocks that will be allowed to access the OriginEndpoint.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.whitelist.is_none()`.
    pub fn whitelist(&self) -> &[::std::string::String] {
        self.whitelist.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for UpdateOriginEndpointOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateOriginEndpointOutput {
    /// Creates a new builder-style object to manufacture [`UpdateOriginEndpointOutput`](crate::operation::update_origin_endpoint::UpdateOriginEndpointOutput).
    pub fn builder() -> crate::operation::update_origin_endpoint::builders::UpdateOriginEndpointOutputBuilder {
        crate::operation::update_origin_endpoint::builders::UpdateOriginEndpointOutputBuilder::default()
    }
}

/// A builder for [`UpdateOriginEndpointOutput`](crate::operation::update_origin_endpoint::UpdateOriginEndpointOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateOriginEndpointOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) authorization: ::std::option::Option<crate::types::Authorization>,
    pub(crate) channel_id: ::std::option::Option<::std::string::String>,
    pub(crate) cmaf_package: ::std::option::Option<crate::types::CmafPackage>,
    pub(crate) created_at: ::std::option::Option<::std::string::String>,
    pub(crate) dash_package: ::std::option::Option<crate::types::DashPackage>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) hls_package: ::std::option::Option<crate::types::HlsPackage>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) manifest_name: ::std::option::Option<::std::string::String>,
    pub(crate) mss_package: ::std::option::Option<crate::types::MssPackage>,
    pub(crate) origination: ::std::option::Option<crate::types::Origination>,
    pub(crate) startover_window_seconds: ::std::option::Option<i32>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) time_delay_seconds: ::std::option::Option<i32>,
    pub(crate) url: ::std::option::Option<::std::string::String>,
    pub(crate) whitelist: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl UpdateOriginEndpointOutputBuilder {
    /// The Amazon Resource Name (ARN) assigned to the OriginEndpoint.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// The Amazon Resource Name (ARN) assigned to the OriginEndpoint.
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// The Amazon Resource Name (ARN) assigned to the OriginEndpoint.
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// CDN Authorization credentials
    pub fn authorization(mut self, input: crate::types::Authorization) -> Self {
        self.authorization = ::std::option::Option::Some(input);
        self
    }
    /// CDN Authorization credentials
    pub fn set_authorization(mut self, input: ::std::option::Option<crate::types::Authorization>) -> Self {
        self.authorization = input;
        self
    }
    /// CDN Authorization credentials
    pub fn get_authorization(&self) -> &::std::option::Option<crate::types::Authorization> {
        &self.authorization
    }
    /// The ID of the Channel the OriginEndpoint is associated with.
    pub fn channel_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_id = ::std::option::Option::Some(input.into());
        self
    }
    /// The ID of the Channel the OriginEndpoint is associated with.
    pub fn set_channel_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_id = input;
        self
    }
    /// The ID of the Channel the OriginEndpoint is associated with.
    pub fn get_channel_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_id
    }
    /// A Common Media Application Format (CMAF) packaging configuration.
    pub fn cmaf_package(mut self, input: crate::types::CmafPackage) -> Self {
        self.cmaf_package = ::std::option::Option::Some(input);
        self
    }
    /// A Common Media Application Format (CMAF) packaging configuration.
    pub fn set_cmaf_package(mut self, input: ::std::option::Option<crate::types::CmafPackage>) -> Self {
        self.cmaf_package = input;
        self
    }
    /// A Common Media Application Format (CMAF) packaging configuration.
    pub fn get_cmaf_package(&self) -> &::std::option::Option<crate::types::CmafPackage> {
        &self.cmaf_package
    }
    /// The date and time the OriginEndpoint was created.
    pub fn created_at(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_at = ::std::option::Option::Some(input.into());
        self
    }
    /// The date and time the OriginEndpoint was created.
    pub fn set_created_at(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_at = input;
        self
    }
    /// The date and time the OriginEndpoint was created.
    pub fn get_created_at(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_at
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
    /// A short text description of the OriginEndpoint.
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// A short text description of the OriginEndpoint.
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// A short text description of the OriginEndpoint.
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
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
    /// The ID of the OriginEndpoint.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// The ID of the OriginEndpoint.
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// The ID of the OriginEndpoint.
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// A short string appended to the end of the OriginEndpoint URL.
    pub fn manifest_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.manifest_name = ::std::option::Option::Some(input.into());
        self
    }
    /// A short string appended to the end of the OriginEndpoint URL.
    pub fn set_manifest_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.manifest_name = input;
        self
    }
    /// A short string appended to the end of the OriginEndpoint URL.
    pub fn get_manifest_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.manifest_name
    }
    /// A Microsoft Smooth Streaming (MSS) packaging configuration.
    pub fn mss_package(mut self, input: crate::types::MssPackage) -> Self {
        self.mss_package = ::std::option::Option::Some(input);
        self
    }
    /// A Microsoft Smooth Streaming (MSS) packaging configuration.
    pub fn set_mss_package(mut self, input: ::std::option::Option<crate::types::MssPackage>) -> Self {
        self.mss_package = input;
        self
    }
    /// A Microsoft Smooth Streaming (MSS) packaging configuration.
    pub fn get_mss_package(&self) -> &::std::option::Option<crate::types::MssPackage> {
        &self.mss_package
    }
    /// Control whether origination of video is allowed for this OriginEndpoint. If set to ALLOW, the OriginEndpoint may by requested, pursuant to any other form of access control. If set to DENY, the OriginEndpoint may not be requested. This can be helpful for Live to VOD harvesting, or for temporarily disabling origination
    pub fn origination(mut self, input: crate::types::Origination) -> Self {
        self.origination = ::std::option::Option::Some(input);
        self
    }
    /// Control whether origination of video is allowed for this OriginEndpoint. If set to ALLOW, the OriginEndpoint may by requested, pursuant to any other form of access control. If set to DENY, the OriginEndpoint may not be requested. This can be helpful for Live to VOD harvesting, or for temporarily disabling origination
    pub fn set_origination(mut self, input: ::std::option::Option<crate::types::Origination>) -> Self {
        self.origination = input;
        self
    }
    /// Control whether origination of video is allowed for this OriginEndpoint. If set to ALLOW, the OriginEndpoint may by requested, pursuant to any other form of access control. If set to DENY, the OriginEndpoint may not be requested. This can be helpful for Live to VOD harvesting, or for temporarily disabling origination
    pub fn get_origination(&self) -> &::std::option::Option<crate::types::Origination> {
        &self.origination
    }
    /// Maximum duration (seconds) of content to retain for startover playback. If not specified, startover playback will be disabled for the OriginEndpoint.
    pub fn startover_window_seconds(mut self, input: i32) -> Self {
        self.startover_window_seconds = ::std::option::Option::Some(input);
        self
    }
    /// Maximum duration (seconds) of content to retain for startover playback. If not specified, startover playback will be disabled for the OriginEndpoint.
    pub fn set_startover_window_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.startover_window_seconds = input;
        self
    }
    /// Maximum duration (seconds) of content to retain for startover playback. If not specified, startover playback will be disabled for the OriginEndpoint.
    pub fn get_startover_window_seconds(&self) -> &::std::option::Option<i32> {
        &self.startover_window_seconds
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
    /// Amount of delay (seconds) to enforce on the playback of live content. If not specified, there will be no time delay in effect for the OriginEndpoint.
    pub fn time_delay_seconds(mut self, input: i32) -> Self {
        self.time_delay_seconds = ::std::option::Option::Some(input);
        self
    }
    /// Amount of delay (seconds) to enforce on the playback of live content. If not specified, there will be no time delay in effect for the OriginEndpoint.
    pub fn set_time_delay_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.time_delay_seconds = input;
        self
    }
    /// Amount of delay (seconds) to enforce on the playback of live content. If not specified, there will be no time delay in effect for the OriginEndpoint.
    pub fn get_time_delay_seconds(&self) -> &::std::option::Option<i32> {
        &self.time_delay_seconds
    }
    /// The URL of the packaged OriginEndpoint for consumption.
    pub fn url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.url = ::std::option::Option::Some(input.into());
        self
    }
    /// The URL of the packaged OriginEndpoint for consumption.
    pub fn set_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.url = input;
        self
    }
    /// The URL of the packaged OriginEndpoint for consumption.
    pub fn get_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.url
    }
    /// Appends an item to `whitelist`.
    ///
    /// To override the contents of this collection use [`set_whitelist`](Self::set_whitelist).
    ///
    /// A list of source IP CIDR blocks that will be allowed to access the OriginEndpoint.
    pub fn whitelist(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.whitelist.unwrap_or_default();
        v.push(input.into());
        self.whitelist = ::std::option::Option::Some(v);
        self
    }
    /// A list of source IP CIDR blocks that will be allowed to access the OriginEndpoint.
    pub fn set_whitelist(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.whitelist = input;
        self
    }
    /// A list of source IP CIDR blocks that will be allowed to access the OriginEndpoint.
    pub fn get_whitelist(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.whitelist
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateOriginEndpointOutput`](crate::operation::update_origin_endpoint::UpdateOriginEndpointOutput).
    pub fn build(self) -> crate::operation::update_origin_endpoint::UpdateOriginEndpointOutput {
        crate::operation::update_origin_endpoint::UpdateOriginEndpointOutput {
            arn: self.arn,
            authorization: self.authorization,
            channel_id: self.channel_id,
            cmaf_package: self.cmaf_package,
            created_at: self.created_at,
            dash_package: self.dash_package,
            description: self.description,
            hls_package: self.hls_package,
            id: self.id,
            manifest_name: self.manifest_name,
            mss_package: self.mss_package,
            origination: self.origination,
            startover_window_seconds: self.startover_window_seconds,
            tags: self.tags,
            time_delay_seconds: self.time_delay_seconds,
            url: self.url,
            whitelist: self.whitelist,
            _request_id: self._request_id,
        }
    }
}
