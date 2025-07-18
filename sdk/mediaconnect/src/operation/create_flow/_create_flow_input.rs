// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateFlowInput {
    /// <p>The Availability Zone that you want to create the flow in. These options are limited to the Availability Zones within the current Amazon Web Services Region.</p>
    pub availability_zone: ::std::option::Option<::std::string::String>,
    /// <p>The entitlements that you want to grant on a flow.</p>
    pub entitlements: ::std::option::Option<::std::vec::Vec<crate::types::GrantEntitlementRequest>>,
    /// <p>The media streams that you want to add to the flow. You can associate these media streams with sources and outputs on the flow.</p>
    pub media_streams: ::std::option::Option<::std::vec::Vec<crate::types::AddMediaStreamRequest>>,
    /// <p>The name of the flow.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The outputs that you want to add to this flow.</p>
    pub outputs: ::std::option::Option<::std::vec::Vec<crate::types::AddOutputRequest>>,
    /// <p>The settings for the source that you want to use for the new flow.</p>
    pub source: ::std::option::Option<crate::types::SetSourceRequest>,
    /// <p>The settings for source failover.</p>
    pub source_failover_config: ::std::option::Option<crate::types::FailoverConfig>,
    /// <p>The sources that are assigned to the flow.</p>
    pub sources: ::std::option::Option<::std::vec::Vec<crate::types::SetSourceRequest>>,
    /// <p>The VPC interfaces you want on the flow.</p>
    pub vpc_interfaces: ::std::option::Option<::std::vec::Vec<crate::types::VpcInterfaceRequest>>,
    /// <p>The maintenance settings you want to use for the flow.</p>
    pub maintenance: ::std::option::Option<crate::types::AddMaintenance>,
    /// <p>The settings for source monitoring.</p>
    pub source_monitoring_config: ::std::option::Option<crate::types::MonitoringConfig>,
    /// <p>Determines the processing capacity and feature set of the flow. Set this optional parameter to <code>LARGE</code> if you want to enable NDI outputs on the flow.</p>
    pub flow_size: ::std::option::Option<crate::types::FlowSize>,
    /// <p>Specifies the configuration settings for NDI outputs. Required when the flow includes NDI outputs.</p>
    pub ndi_config: ::std::option::Option<crate::types::NdiConfig>,
}
impl CreateFlowInput {
    /// <p>The Availability Zone that you want to create the flow in. These options are limited to the Availability Zones within the current Amazon Web Services Region.</p>
    pub fn availability_zone(&self) -> ::std::option::Option<&str> {
        self.availability_zone.as_deref()
    }
    /// <p>The entitlements that you want to grant on a flow.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.entitlements.is_none()`.
    pub fn entitlements(&self) -> &[crate::types::GrantEntitlementRequest] {
        self.entitlements.as_deref().unwrap_or_default()
    }
    /// <p>The media streams that you want to add to the flow. You can associate these media streams with sources and outputs on the flow.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.media_streams.is_none()`.
    pub fn media_streams(&self) -> &[crate::types::AddMediaStreamRequest] {
        self.media_streams.as_deref().unwrap_or_default()
    }
    /// <p>The name of the flow.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The outputs that you want to add to this flow.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.outputs.is_none()`.
    pub fn outputs(&self) -> &[crate::types::AddOutputRequest] {
        self.outputs.as_deref().unwrap_or_default()
    }
    /// <p>The settings for the source that you want to use for the new flow.</p>
    pub fn source(&self) -> ::std::option::Option<&crate::types::SetSourceRequest> {
        self.source.as_ref()
    }
    /// <p>The settings for source failover.</p>
    pub fn source_failover_config(&self) -> ::std::option::Option<&crate::types::FailoverConfig> {
        self.source_failover_config.as_ref()
    }
    /// <p>The sources that are assigned to the flow.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sources.is_none()`.
    pub fn sources(&self) -> &[crate::types::SetSourceRequest] {
        self.sources.as_deref().unwrap_or_default()
    }
    /// <p>The VPC interfaces you want on the flow.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.vpc_interfaces.is_none()`.
    pub fn vpc_interfaces(&self) -> &[crate::types::VpcInterfaceRequest] {
        self.vpc_interfaces.as_deref().unwrap_or_default()
    }
    /// <p>The maintenance settings you want to use for the flow.</p>
    pub fn maintenance(&self) -> ::std::option::Option<&crate::types::AddMaintenance> {
        self.maintenance.as_ref()
    }
    /// <p>The settings for source monitoring.</p>
    pub fn source_monitoring_config(&self) -> ::std::option::Option<&crate::types::MonitoringConfig> {
        self.source_monitoring_config.as_ref()
    }
    /// <p>Determines the processing capacity and feature set of the flow. Set this optional parameter to <code>LARGE</code> if you want to enable NDI outputs on the flow.</p>
    pub fn flow_size(&self) -> ::std::option::Option<&crate::types::FlowSize> {
        self.flow_size.as_ref()
    }
    /// <p>Specifies the configuration settings for NDI outputs. Required when the flow includes NDI outputs.</p>
    pub fn ndi_config(&self) -> ::std::option::Option<&crate::types::NdiConfig> {
        self.ndi_config.as_ref()
    }
}
impl CreateFlowInput {
    /// Creates a new builder-style object to manufacture [`CreateFlowInput`](crate::operation::create_flow::CreateFlowInput).
    pub fn builder() -> crate::operation::create_flow::builders::CreateFlowInputBuilder {
        crate::operation::create_flow::builders::CreateFlowInputBuilder::default()
    }
}

/// A builder for [`CreateFlowInput`](crate::operation::create_flow::CreateFlowInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateFlowInputBuilder {
    pub(crate) availability_zone: ::std::option::Option<::std::string::String>,
    pub(crate) entitlements: ::std::option::Option<::std::vec::Vec<crate::types::GrantEntitlementRequest>>,
    pub(crate) media_streams: ::std::option::Option<::std::vec::Vec<crate::types::AddMediaStreamRequest>>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) outputs: ::std::option::Option<::std::vec::Vec<crate::types::AddOutputRequest>>,
    pub(crate) source: ::std::option::Option<crate::types::SetSourceRequest>,
    pub(crate) source_failover_config: ::std::option::Option<crate::types::FailoverConfig>,
    pub(crate) sources: ::std::option::Option<::std::vec::Vec<crate::types::SetSourceRequest>>,
    pub(crate) vpc_interfaces: ::std::option::Option<::std::vec::Vec<crate::types::VpcInterfaceRequest>>,
    pub(crate) maintenance: ::std::option::Option<crate::types::AddMaintenance>,
    pub(crate) source_monitoring_config: ::std::option::Option<crate::types::MonitoringConfig>,
    pub(crate) flow_size: ::std::option::Option<crate::types::FlowSize>,
    pub(crate) ndi_config: ::std::option::Option<crate::types::NdiConfig>,
}
impl CreateFlowInputBuilder {
    /// <p>The Availability Zone that you want to create the flow in. These options are limited to the Availability Zones within the current Amazon Web Services Region.</p>
    pub fn availability_zone(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.availability_zone = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Availability Zone that you want to create the flow in. These options are limited to the Availability Zones within the current Amazon Web Services Region.</p>
    pub fn set_availability_zone(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.availability_zone = input;
        self
    }
    /// <p>The Availability Zone that you want to create the flow in. These options are limited to the Availability Zones within the current Amazon Web Services Region.</p>
    pub fn get_availability_zone(&self) -> &::std::option::Option<::std::string::String> {
        &self.availability_zone
    }
    /// Appends an item to `entitlements`.
    ///
    /// To override the contents of this collection use [`set_entitlements`](Self::set_entitlements).
    ///
    /// <p>The entitlements that you want to grant on a flow.</p>
    pub fn entitlements(mut self, input: crate::types::GrantEntitlementRequest) -> Self {
        let mut v = self.entitlements.unwrap_or_default();
        v.push(input);
        self.entitlements = ::std::option::Option::Some(v);
        self
    }
    /// <p>The entitlements that you want to grant on a flow.</p>
    pub fn set_entitlements(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GrantEntitlementRequest>>) -> Self {
        self.entitlements = input;
        self
    }
    /// <p>The entitlements that you want to grant on a flow.</p>
    pub fn get_entitlements(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GrantEntitlementRequest>> {
        &self.entitlements
    }
    /// Appends an item to `media_streams`.
    ///
    /// To override the contents of this collection use [`set_media_streams`](Self::set_media_streams).
    ///
    /// <p>The media streams that you want to add to the flow. You can associate these media streams with sources and outputs on the flow.</p>
    pub fn media_streams(mut self, input: crate::types::AddMediaStreamRequest) -> Self {
        let mut v = self.media_streams.unwrap_or_default();
        v.push(input);
        self.media_streams = ::std::option::Option::Some(v);
        self
    }
    /// <p>The media streams that you want to add to the flow. You can associate these media streams with sources and outputs on the flow.</p>
    pub fn set_media_streams(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AddMediaStreamRequest>>) -> Self {
        self.media_streams = input;
        self
    }
    /// <p>The media streams that you want to add to the flow. You can associate these media streams with sources and outputs on the flow.</p>
    pub fn get_media_streams(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AddMediaStreamRequest>> {
        &self.media_streams
    }
    /// <p>The name of the flow.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the flow.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the flow.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `outputs`.
    ///
    /// To override the contents of this collection use [`set_outputs`](Self::set_outputs).
    ///
    /// <p>The outputs that you want to add to this flow.</p>
    pub fn outputs(mut self, input: crate::types::AddOutputRequest) -> Self {
        let mut v = self.outputs.unwrap_or_default();
        v.push(input);
        self.outputs = ::std::option::Option::Some(v);
        self
    }
    /// <p>The outputs that you want to add to this flow.</p>
    pub fn set_outputs(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AddOutputRequest>>) -> Self {
        self.outputs = input;
        self
    }
    /// <p>The outputs that you want to add to this flow.</p>
    pub fn get_outputs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AddOutputRequest>> {
        &self.outputs
    }
    /// <p>The settings for the source that you want to use for the new flow.</p>
    pub fn source(mut self, input: crate::types::SetSourceRequest) -> Self {
        self.source = ::std::option::Option::Some(input);
        self
    }
    /// <p>The settings for the source that you want to use for the new flow.</p>
    pub fn set_source(mut self, input: ::std::option::Option<crate::types::SetSourceRequest>) -> Self {
        self.source = input;
        self
    }
    /// <p>The settings for the source that you want to use for the new flow.</p>
    pub fn get_source(&self) -> &::std::option::Option<crate::types::SetSourceRequest> {
        &self.source
    }
    /// <p>The settings for source failover.</p>
    pub fn source_failover_config(mut self, input: crate::types::FailoverConfig) -> Self {
        self.source_failover_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The settings for source failover.</p>
    pub fn set_source_failover_config(mut self, input: ::std::option::Option<crate::types::FailoverConfig>) -> Self {
        self.source_failover_config = input;
        self
    }
    /// <p>The settings for source failover.</p>
    pub fn get_source_failover_config(&self) -> &::std::option::Option<crate::types::FailoverConfig> {
        &self.source_failover_config
    }
    /// Appends an item to `sources`.
    ///
    /// To override the contents of this collection use [`set_sources`](Self::set_sources).
    ///
    /// <p>The sources that are assigned to the flow.</p>
    pub fn sources(mut self, input: crate::types::SetSourceRequest) -> Self {
        let mut v = self.sources.unwrap_or_default();
        v.push(input);
        self.sources = ::std::option::Option::Some(v);
        self
    }
    /// <p>The sources that are assigned to the flow.</p>
    pub fn set_sources(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SetSourceRequest>>) -> Self {
        self.sources = input;
        self
    }
    /// <p>The sources that are assigned to the flow.</p>
    pub fn get_sources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SetSourceRequest>> {
        &self.sources
    }
    /// Appends an item to `vpc_interfaces`.
    ///
    /// To override the contents of this collection use [`set_vpc_interfaces`](Self::set_vpc_interfaces).
    ///
    /// <p>The VPC interfaces you want on the flow.</p>
    pub fn vpc_interfaces(mut self, input: crate::types::VpcInterfaceRequest) -> Self {
        let mut v = self.vpc_interfaces.unwrap_or_default();
        v.push(input);
        self.vpc_interfaces = ::std::option::Option::Some(v);
        self
    }
    /// <p>The VPC interfaces you want on the flow.</p>
    pub fn set_vpc_interfaces(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::VpcInterfaceRequest>>) -> Self {
        self.vpc_interfaces = input;
        self
    }
    /// <p>The VPC interfaces you want on the flow.</p>
    pub fn get_vpc_interfaces(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::VpcInterfaceRequest>> {
        &self.vpc_interfaces
    }
    /// <p>The maintenance settings you want to use for the flow.</p>
    pub fn maintenance(mut self, input: crate::types::AddMaintenance) -> Self {
        self.maintenance = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maintenance settings you want to use for the flow.</p>
    pub fn set_maintenance(mut self, input: ::std::option::Option<crate::types::AddMaintenance>) -> Self {
        self.maintenance = input;
        self
    }
    /// <p>The maintenance settings you want to use for the flow.</p>
    pub fn get_maintenance(&self) -> &::std::option::Option<crate::types::AddMaintenance> {
        &self.maintenance
    }
    /// <p>The settings for source monitoring.</p>
    pub fn source_monitoring_config(mut self, input: crate::types::MonitoringConfig) -> Self {
        self.source_monitoring_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The settings for source monitoring.</p>
    pub fn set_source_monitoring_config(mut self, input: ::std::option::Option<crate::types::MonitoringConfig>) -> Self {
        self.source_monitoring_config = input;
        self
    }
    /// <p>The settings for source monitoring.</p>
    pub fn get_source_monitoring_config(&self) -> &::std::option::Option<crate::types::MonitoringConfig> {
        &self.source_monitoring_config
    }
    /// <p>Determines the processing capacity and feature set of the flow. Set this optional parameter to <code>LARGE</code> if you want to enable NDI outputs on the flow.</p>
    pub fn flow_size(mut self, input: crate::types::FlowSize) -> Self {
        self.flow_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>Determines the processing capacity and feature set of the flow. Set this optional parameter to <code>LARGE</code> if you want to enable NDI outputs on the flow.</p>
    pub fn set_flow_size(mut self, input: ::std::option::Option<crate::types::FlowSize>) -> Self {
        self.flow_size = input;
        self
    }
    /// <p>Determines the processing capacity and feature set of the flow. Set this optional parameter to <code>LARGE</code> if you want to enable NDI outputs on the flow.</p>
    pub fn get_flow_size(&self) -> &::std::option::Option<crate::types::FlowSize> {
        &self.flow_size
    }
    /// <p>Specifies the configuration settings for NDI outputs. Required when the flow includes NDI outputs.</p>
    pub fn ndi_config(mut self, input: crate::types::NdiConfig) -> Self {
        self.ndi_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the configuration settings for NDI outputs. Required when the flow includes NDI outputs.</p>
    pub fn set_ndi_config(mut self, input: ::std::option::Option<crate::types::NdiConfig>) -> Self {
        self.ndi_config = input;
        self
    }
    /// <p>Specifies the configuration settings for NDI outputs. Required when the flow includes NDI outputs.</p>
    pub fn get_ndi_config(&self) -> &::std::option::Option<crate::types::NdiConfig> {
        &self.ndi_config
    }
    /// Consumes the builder and constructs a [`CreateFlowInput`](crate::operation::create_flow::CreateFlowInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_flow::CreateFlowInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_flow::CreateFlowInput {
            availability_zone: self.availability_zone,
            entitlements: self.entitlements,
            media_streams: self.media_streams,
            name: self.name,
            outputs: self.outputs,
            source: self.source,
            source_failover_config: self.source_failover_config,
            sources: self.sources,
            vpc_interfaces: self.vpc_interfaces,
            maintenance: self.maintenance,
            source_monitoring_config: self.source_monitoring_config,
            flow_size: self.flow_size,
            ndi_config: self.ndi_config,
        })
    }
}
