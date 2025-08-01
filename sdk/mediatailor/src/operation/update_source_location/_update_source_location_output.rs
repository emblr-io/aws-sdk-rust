// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateSourceLocationOutput {
    /// <p>Access configuration parameters. Configures the type of authentication used to access content from your source location.</p>
    pub access_configuration: ::std::option::Option<crate::types::AccessConfiguration>,
    /// <p>The Amazon Resource Name (ARN) associated with the source location.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp that indicates when the source location was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The optional configuration for the host server that serves segments.</p>
    pub default_segment_delivery_configuration: ::std::option::Option<crate::types::DefaultSegmentDeliveryConfiguration>,
    /// <p>The HTTP configuration for the source location.</p>
    pub http_configuration: ::std::option::Option<crate::types::HttpConfiguration>,
    /// <p>The timestamp that indicates when the source location was last modified.</p>
    pub last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The segment delivery configurations for the source location. For information about MediaTailor configurations, see <a href="https://docs.aws.amazon.com/mediatailor/latest/ug/configurations.html">Working with configurations in AWS Elemental MediaTailor</a>.</p>
    pub segment_delivery_configurations: ::std::option::Option<::std::vec::Vec<crate::types::SegmentDeliveryConfiguration>>,
    /// <p>The name of the source location.</p>
    pub source_location_name: ::std::option::Option<::std::string::String>,
    /// <p>The tags to assign to the source location. Tags are key-value pairs that you can associate with Amazon resources to help with organization, access control, and cost tracking. For more information, see <a href="https://docs.aws.amazon.com/mediatailor/latest/ug/tagging.html">Tagging AWS Elemental MediaTailor Resources</a>.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl UpdateSourceLocationOutput {
    /// <p>Access configuration parameters. Configures the type of authentication used to access content from your source location.</p>
    pub fn access_configuration(&self) -> ::std::option::Option<&crate::types::AccessConfiguration> {
        self.access_configuration.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) associated with the source location.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The timestamp that indicates when the source location was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>The optional configuration for the host server that serves segments.</p>
    pub fn default_segment_delivery_configuration(&self) -> ::std::option::Option<&crate::types::DefaultSegmentDeliveryConfiguration> {
        self.default_segment_delivery_configuration.as_ref()
    }
    /// <p>The HTTP configuration for the source location.</p>
    pub fn http_configuration(&self) -> ::std::option::Option<&crate::types::HttpConfiguration> {
        self.http_configuration.as_ref()
    }
    /// <p>The timestamp that indicates when the source location was last modified.</p>
    pub fn last_modified_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_time.as_ref()
    }
    /// <p>The segment delivery configurations for the source location. For information about MediaTailor configurations, see <a href="https://docs.aws.amazon.com/mediatailor/latest/ug/configurations.html">Working with configurations in AWS Elemental MediaTailor</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.segment_delivery_configurations.is_none()`.
    pub fn segment_delivery_configurations(&self) -> &[crate::types::SegmentDeliveryConfiguration] {
        self.segment_delivery_configurations.as_deref().unwrap_or_default()
    }
    /// <p>The name of the source location.</p>
    pub fn source_location_name(&self) -> ::std::option::Option<&str> {
        self.source_location_name.as_deref()
    }
    /// <p>The tags to assign to the source location. Tags are key-value pairs that you can associate with Amazon resources to help with organization, access control, and cost tracking. For more information, see <a href="https://docs.aws.amazon.com/mediatailor/latest/ug/tagging.html">Tagging AWS Elemental MediaTailor Resources</a>.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateSourceLocationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateSourceLocationOutput {
    /// Creates a new builder-style object to manufacture [`UpdateSourceLocationOutput`](crate::operation::update_source_location::UpdateSourceLocationOutput).
    pub fn builder() -> crate::operation::update_source_location::builders::UpdateSourceLocationOutputBuilder {
        crate::operation::update_source_location::builders::UpdateSourceLocationOutputBuilder::default()
    }
}

/// A builder for [`UpdateSourceLocationOutput`](crate::operation::update_source_location::UpdateSourceLocationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateSourceLocationOutputBuilder {
    pub(crate) access_configuration: ::std::option::Option<crate::types::AccessConfiguration>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) default_segment_delivery_configuration: ::std::option::Option<crate::types::DefaultSegmentDeliveryConfiguration>,
    pub(crate) http_configuration: ::std::option::Option<crate::types::HttpConfiguration>,
    pub(crate) last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) segment_delivery_configurations: ::std::option::Option<::std::vec::Vec<crate::types::SegmentDeliveryConfiguration>>,
    pub(crate) source_location_name: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl UpdateSourceLocationOutputBuilder {
    /// <p>Access configuration parameters. Configures the type of authentication used to access content from your source location.</p>
    pub fn access_configuration(mut self, input: crate::types::AccessConfiguration) -> Self {
        self.access_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Access configuration parameters. Configures the type of authentication used to access content from your source location.</p>
    pub fn set_access_configuration(mut self, input: ::std::option::Option<crate::types::AccessConfiguration>) -> Self {
        self.access_configuration = input;
        self
    }
    /// <p>Access configuration parameters. Configures the type of authentication used to access content from your source location.</p>
    pub fn get_access_configuration(&self) -> &::std::option::Option<crate::types::AccessConfiguration> {
        &self.access_configuration
    }
    /// <p>The Amazon Resource Name (ARN) associated with the source location.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) associated with the source location.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) associated with the source location.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The timestamp that indicates when the source location was created.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp that indicates when the source location was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The timestamp that indicates when the source location was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>The optional configuration for the host server that serves segments.</p>
    pub fn default_segment_delivery_configuration(mut self, input: crate::types::DefaultSegmentDeliveryConfiguration) -> Self {
        self.default_segment_delivery_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The optional configuration for the host server that serves segments.</p>
    pub fn set_default_segment_delivery_configuration(
        mut self,
        input: ::std::option::Option<crate::types::DefaultSegmentDeliveryConfiguration>,
    ) -> Self {
        self.default_segment_delivery_configuration = input;
        self
    }
    /// <p>The optional configuration for the host server that serves segments.</p>
    pub fn get_default_segment_delivery_configuration(&self) -> &::std::option::Option<crate::types::DefaultSegmentDeliveryConfiguration> {
        &self.default_segment_delivery_configuration
    }
    /// <p>The HTTP configuration for the source location.</p>
    pub fn http_configuration(mut self, input: crate::types::HttpConfiguration) -> Self {
        self.http_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The HTTP configuration for the source location.</p>
    pub fn set_http_configuration(mut self, input: ::std::option::Option<crate::types::HttpConfiguration>) -> Self {
        self.http_configuration = input;
        self
    }
    /// <p>The HTTP configuration for the source location.</p>
    pub fn get_http_configuration(&self) -> &::std::option::Option<crate::types::HttpConfiguration> {
        &self.http_configuration
    }
    /// <p>The timestamp that indicates when the source location was last modified.</p>
    pub fn last_modified_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp that indicates when the source location was last modified.</p>
    pub fn set_last_modified_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time = input;
        self
    }
    /// <p>The timestamp that indicates when the source location was last modified.</p>
    pub fn get_last_modified_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time
    }
    /// Appends an item to `segment_delivery_configurations`.
    ///
    /// To override the contents of this collection use [`set_segment_delivery_configurations`](Self::set_segment_delivery_configurations).
    ///
    /// <p>The segment delivery configurations for the source location. For information about MediaTailor configurations, see <a href="https://docs.aws.amazon.com/mediatailor/latest/ug/configurations.html">Working with configurations in AWS Elemental MediaTailor</a>.</p>
    pub fn segment_delivery_configurations(mut self, input: crate::types::SegmentDeliveryConfiguration) -> Self {
        let mut v = self.segment_delivery_configurations.unwrap_or_default();
        v.push(input);
        self.segment_delivery_configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>The segment delivery configurations for the source location. For information about MediaTailor configurations, see <a href="https://docs.aws.amazon.com/mediatailor/latest/ug/configurations.html">Working with configurations in AWS Elemental MediaTailor</a>.</p>
    pub fn set_segment_delivery_configurations(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::SegmentDeliveryConfiguration>>,
    ) -> Self {
        self.segment_delivery_configurations = input;
        self
    }
    /// <p>The segment delivery configurations for the source location. For information about MediaTailor configurations, see <a href="https://docs.aws.amazon.com/mediatailor/latest/ug/configurations.html">Working with configurations in AWS Elemental MediaTailor</a>.</p>
    pub fn get_segment_delivery_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SegmentDeliveryConfiguration>> {
        &self.segment_delivery_configurations
    }
    /// <p>The name of the source location.</p>
    pub fn source_location_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_location_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the source location.</p>
    pub fn set_source_location_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_location_name = input;
        self
    }
    /// <p>The name of the source location.</p>
    pub fn get_source_location_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_location_name
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags to assign to the source location. Tags are key-value pairs that you can associate with Amazon resources to help with organization, access control, and cost tracking. For more information, see <a href="https://docs.aws.amazon.com/mediatailor/latest/ug/tagging.html">Tagging AWS Elemental MediaTailor Resources</a>.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags to assign to the source location. Tags are key-value pairs that you can associate with Amazon resources to help with organization, access control, and cost tracking. For more information, see <a href="https://docs.aws.amazon.com/mediatailor/latest/ug/tagging.html">Tagging AWS Elemental MediaTailor Resources</a>.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags to assign to the source location. Tags are key-value pairs that you can associate with Amazon resources to help with organization, access control, and cost tracking. For more information, see <a href="https://docs.aws.amazon.com/mediatailor/latest/ug/tagging.html">Tagging AWS Elemental MediaTailor Resources</a>.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateSourceLocationOutput`](crate::operation::update_source_location::UpdateSourceLocationOutput).
    pub fn build(self) -> crate::operation::update_source_location::UpdateSourceLocationOutput {
        crate::operation::update_source_location::UpdateSourceLocationOutput {
            access_configuration: self.access_configuration,
            arn: self.arn,
            creation_time: self.creation_time,
            default_segment_delivery_configuration: self.default_segment_delivery_configuration,
            http_configuration: self.http_configuration,
            last_modified_time: self.last_modified_time,
            segment_delivery_configurations: self.segment_delivery_configurations,
            source_location_name: self.source_location_name,
            tags: self.tags,
            _request_id: self._request_id,
        }
    }
}
