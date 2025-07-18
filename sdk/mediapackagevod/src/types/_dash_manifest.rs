// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// A DASH manifest configuration.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DashManifest {
    /// Determines the position of some tags in the Media Presentation Description (MPD). When set to FULL, elements like SegmentTemplate and ContentProtection are included in each Representation. When set to COMPACT, duplicate elements are combined and presented at the AdaptationSet level.
    pub manifest_layout: ::std::option::Option<crate::types::ManifestLayout>,
    /// An optional string to include in the name of the manifest.
    pub manifest_name: ::std::option::Option<::std::string::String>,
    /// Minimum duration (in seconds) that a player will buffer media before starting the presentation.
    pub min_buffer_time_seconds: ::std::option::Option<i32>,
    /// The Dynamic Adaptive Streaming over HTTP (DASH) profile type. When set to "HBBTV_1_5", HbbTV 1.5 compliant output is enabled.
    pub profile: ::std::option::Option<crate::types::Profile>,
    /// The source of scte markers used. When set to SEGMENTS, the scte markers are sourced from the segments of the ingested content. When set to MANIFEST, the scte markers are sourced from the manifest of the ingested content.
    pub scte_markers_source: ::std::option::Option<crate::types::ScteMarkersSource>,
    /// A StreamSelection configuration.
    pub stream_selection: ::std::option::Option<crate::types::StreamSelection>,
}
impl DashManifest {
    /// Determines the position of some tags in the Media Presentation Description (MPD). When set to FULL, elements like SegmentTemplate and ContentProtection are included in each Representation. When set to COMPACT, duplicate elements are combined and presented at the AdaptationSet level.
    pub fn manifest_layout(&self) -> ::std::option::Option<&crate::types::ManifestLayout> {
        self.manifest_layout.as_ref()
    }
    /// An optional string to include in the name of the manifest.
    pub fn manifest_name(&self) -> ::std::option::Option<&str> {
        self.manifest_name.as_deref()
    }
    /// Minimum duration (in seconds) that a player will buffer media before starting the presentation.
    pub fn min_buffer_time_seconds(&self) -> ::std::option::Option<i32> {
        self.min_buffer_time_seconds
    }
    /// The Dynamic Adaptive Streaming over HTTP (DASH) profile type. When set to "HBBTV_1_5", HbbTV 1.5 compliant output is enabled.
    pub fn profile(&self) -> ::std::option::Option<&crate::types::Profile> {
        self.profile.as_ref()
    }
    /// The source of scte markers used. When set to SEGMENTS, the scte markers are sourced from the segments of the ingested content. When set to MANIFEST, the scte markers are sourced from the manifest of the ingested content.
    pub fn scte_markers_source(&self) -> ::std::option::Option<&crate::types::ScteMarkersSource> {
        self.scte_markers_source.as_ref()
    }
    /// A StreamSelection configuration.
    pub fn stream_selection(&self) -> ::std::option::Option<&crate::types::StreamSelection> {
        self.stream_selection.as_ref()
    }
}
impl DashManifest {
    /// Creates a new builder-style object to manufacture [`DashManifest`](crate::types::DashManifest).
    pub fn builder() -> crate::types::builders::DashManifestBuilder {
        crate::types::builders::DashManifestBuilder::default()
    }
}

/// A builder for [`DashManifest`](crate::types::DashManifest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DashManifestBuilder {
    pub(crate) manifest_layout: ::std::option::Option<crate::types::ManifestLayout>,
    pub(crate) manifest_name: ::std::option::Option<::std::string::String>,
    pub(crate) min_buffer_time_seconds: ::std::option::Option<i32>,
    pub(crate) profile: ::std::option::Option<crate::types::Profile>,
    pub(crate) scte_markers_source: ::std::option::Option<crate::types::ScteMarkersSource>,
    pub(crate) stream_selection: ::std::option::Option<crate::types::StreamSelection>,
}
impl DashManifestBuilder {
    /// Determines the position of some tags in the Media Presentation Description (MPD). When set to FULL, elements like SegmentTemplate and ContentProtection are included in each Representation. When set to COMPACT, duplicate elements are combined and presented at the AdaptationSet level.
    pub fn manifest_layout(mut self, input: crate::types::ManifestLayout) -> Self {
        self.manifest_layout = ::std::option::Option::Some(input);
        self
    }
    /// Determines the position of some tags in the Media Presentation Description (MPD). When set to FULL, elements like SegmentTemplate and ContentProtection are included in each Representation. When set to COMPACT, duplicate elements are combined and presented at the AdaptationSet level.
    pub fn set_manifest_layout(mut self, input: ::std::option::Option<crate::types::ManifestLayout>) -> Self {
        self.manifest_layout = input;
        self
    }
    /// Determines the position of some tags in the Media Presentation Description (MPD). When set to FULL, elements like SegmentTemplate and ContentProtection are included in each Representation. When set to COMPACT, duplicate elements are combined and presented at the AdaptationSet level.
    pub fn get_manifest_layout(&self) -> &::std::option::Option<crate::types::ManifestLayout> {
        &self.manifest_layout
    }
    /// An optional string to include in the name of the manifest.
    pub fn manifest_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.manifest_name = ::std::option::Option::Some(input.into());
        self
    }
    /// An optional string to include in the name of the manifest.
    pub fn set_manifest_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.manifest_name = input;
        self
    }
    /// An optional string to include in the name of the manifest.
    pub fn get_manifest_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.manifest_name
    }
    /// Minimum duration (in seconds) that a player will buffer media before starting the presentation.
    pub fn min_buffer_time_seconds(mut self, input: i32) -> Self {
        self.min_buffer_time_seconds = ::std::option::Option::Some(input);
        self
    }
    /// Minimum duration (in seconds) that a player will buffer media before starting the presentation.
    pub fn set_min_buffer_time_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.min_buffer_time_seconds = input;
        self
    }
    /// Minimum duration (in seconds) that a player will buffer media before starting the presentation.
    pub fn get_min_buffer_time_seconds(&self) -> &::std::option::Option<i32> {
        &self.min_buffer_time_seconds
    }
    /// The Dynamic Adaptive Streaming over HTTP (DASH) profile type. When set to "HBBTV_1_5", HbbTV 1.5 compliant output is enabled.
    pub fn profile(mut self, input: crate::types::Profile) -> Self {
        self.profile = ::std::option::Option::Some(input);
        self
    }
    /// The Dynamic Adaptive Streaming over HTTP (DASH) profile type. When set to "HBBTV_1_5", HbbTV 1.5 compliant output is enabled.
    pub fn set_profile(mut self, input: ::std::option::Option<crate::types::Profile>) -> Self {
        self.profile = input;
        self
    }
    /// The Dynamic Adaptive Streaming over HTTP (DASH) profile type. When set to "HBBTV_1_5", HbbTV 1.5 compliant output is enabled.
    pub fn get_profile(&self) -> &::std::option::Option<crate::types::Profile> {
        &self.profile
    }
    /// The source of scte markers used. When set to SEGMENTS, the scte markers are sourced from the segments of the ingested content. When set to MANIFEST, the scte markers are sourced from the manifest of the ingested content.
    pub fn scte_markers_source(mut self, input: crate::types::ScteMarkersSource) -> Self {
        self.scte_markers_source = ::std::option::Option::Some(input);
        self
    }
    /// The source of scte markers used. When set to SEGMENTS, the scte markers are sourced from the segments of the ingested content. When set to MANIFEST, the scte markers are sourced from the manifest of the ingested content.
    pub fn set_scte_markers_source(mut self, input: ::std::option::Option<crate::types::ScteMarkersSource>) -> Self {
        self.scte_markers_source = input;
        self
    }
    /// The source of scte markers used. When set to SEGMENTS, the scte markers are sourced from the segments of the ingested content. When set to MANIFEST, the scte markers are sourced from the manifest of the ingested content.
    pub fn get_scte_markers_source(&self) -> &::std::option::Option<crate::types::ScteMarkersSource> {
        &self.scte_markers_source
    }
    /// A StreamSelection configuration.
    pub fn stream_selection(mut self, input: crate::types::StreamSelection) -> Self {
        self.stream_selection = ::std::option::Option::Some(input);
        self
    }
    /// A StreamSelection configuration.
    pub fn set_stream_selection(mut self, input: ::std::option::Option<crate::types::StreamSelection>) -> Self {
        self.stream_selection = input;
        self
    }
    /// A StreamSelection configuration.
    pub fn get_stream_selection(&self) -> &::std::option::Option<crate::types::StreamSelection> {
        &self.stream_selection
    }
    /// Consumes the builder and constructs a [`DashManifest`](crate::types::DashManifest).
    pub fn build(self) -> crate::types::DashManifest {
        crate::types::DashManifest {
            manifest_layout: self.manifest_layout,
            manifest_name: self.manifest_name,
            min_buffer_time_seconds: self.min_buffer_time_seconds,
            profile: self.profile,
            scte_markers_source: self.scte_markers_source,
            stream_selection: self.stream_selection,
        }
    }
}
