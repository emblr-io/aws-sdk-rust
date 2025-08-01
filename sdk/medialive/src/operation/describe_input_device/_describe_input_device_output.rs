// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Placeholder documentation for DescribeInputDeviceResponse
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeInputDeviceOutput {
    /// The unique ARN of the input device.
    pub arn: ::std::option::Option<::std::string::String>,
    /// The state of the connection between the input device and AWS.
    pub connection_state: ::std::option::Option<crate::types::InputDeviceConnectionState>,
    /// The status of the action to synchronize the device configuration. If you change the configuration of the input device (for example, the maximum bitrate), MediaLive sends the new data to the device. The device might not update itself immediately. SYNCED means the device has updated its configuration. SYNCING means that it has not updated its configuration.
    pub device_settings_sync_state: ::std::option::Option<crate::types::DeviceSettingsSyncState>,
    /// The status of software on the input device.
    pub device_update_status: ::std::option::Option<crate::types::DeviceUpdateStatus>,
    /// Settings that describe an input device that is type HD.
    pub hd_device_settings: ::std::option::Option<crate::types::InputDeviceHdSettings>,
    /// The unique ID of the input device.
    pub id: ::std::option::Option<::std::string::String>,
    /// The network MAC address of the input device.
    pub mac_address: ::std::option::Option<::std::string::String>,
    /// A name that you specify for the input device.
    pub name: ::std::option::Option<::std::string::String>,
    /// The network settings for the input device.
    pub network_settings: ::std::option::Option<crate::types::InputDeviceNetworkSettings>,
    /// The unique serial number of the input device.
    pub serial_number: ::std::option::Option<::std::string::String>,
    /// The type of the input device.
    pub r#type: ::std::option::Option<crate::types::InputDeviceType>,
    /// Settings that describe an input device that is type UHD.
    pub uhd_device_settings: ::std::option::Option<crate::types::InputDeviceUhdSettings>,
    /// A collection of key-value pairs.
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// The Availability Zone associated with this input device.
    pub availability_zone: ::std::option::Option<::std::string::String>,
    /// An array of the ARNs for the MediaLive inputs attached to the device. Returned only if the outputType is MEDIALIVE_INPUT.
    pub medialive_input_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// The output attachment type of the input device. Specifies MEDIACONNECT_FLOW if this device is the source for a MediaConnect flow. Specifies MEDIALIVE_INPUT if this device is the source for a MediaLive input.
    pub output_type: ::std::option::Option<crate::types::InputDeviceOutputType>,
    _request_id: Option<String>,
}
impl DescribeInputDeviceOutput {
    /// The unique ARN of the input device.
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// The state of the connection between the input device and AWS.
    pub fn connection_state(&self) -> ::std::option::Option<&crate::types::InputDeviceConnectionState> {
        self.connection_state.as_ref()
    }
    /// The status of the action to synchronize the device configuration. If you change the configuration of the input device (for example, the maximum bitrate), MediaLive sends the new data to the device. The device might not update itself immediately. SYNCED means the device has updated its configuration. SYNCING means that it has not updated its configuration.
    pub fn device_settings_sync_state(&self) -> ::std::option::Option<&crate::types::DeviceSettingsSyncState> {
        self.device_settings_sync_state.as_ref()
    }
    /// The status of software on the input device.
    pub fn device_update_status(&self) -> ::std::option::Option<&crate::types::DeviceUpdateStatus> {
        self.device_update_status.as_ref()
    }
    /// Settings that describe an input device that is type HD.
    pub fn hd_device_settings(&self) -> ::std::option::Option<&crate::types::InputDeviceHdSettings> {
        self.hd_device_settings.as_ref()
    }
    /// The unique ID of the input device.
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// The network MAC address of the input device.
    pub fn mac_address(&self) -> ::std::option::Option<&str> {
        self.mac_address.as_deref()
    }
    /// A name that you specify for the input device.
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// The network settings for the input device.
    pub fn network_settings(&self) -> ::std::option::Option<&crate::types::InputDeviceNetworkSettings> {
        self.network_settings.as_ref()
    }
    /// The unique serial number of the input device.
    pub fn serial_number(&self) -> ::std::option::Option<&str> {
        self.serial_number.as_deref()
    }
    /// The type of the input device.
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::InputDeviceType> {
        self.r#type.as_ref()
    }
    /// Settings that describe an input device that is type UHD.
    pub fn uhd_device_settings(&self) -> ::std::option::Option<&crate::types::InputDeviceUhdSettings> {
        self.uhd_device_settings.as_ref()
    }
    /// A collection of key-value pairs.
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// The Availability Zone associated with this input device.
    pub fn availability_zone(&self) -> ::std::option::Option<&str> {
        self.availability_zone.as_deref()
    }
    /// An array of the ARNs for the MediaLive inputs attached to the device. Returned only if the outputType is MEDIALIVE_INPUT.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.medialive_input_arns.is_none()`.
    pub fn medialive_input_arns(&self) -> &[::std::string::String] {
        self.medialive_input_arns.as_deref().unwrap_or_default()
    }
    /// The output attachment type of the input device. Specifies MEDIACONNECT_FLOW if this device is the source for a MediaConnect flow. Specifies MEDIALIVE_INPUT if this device is the source for a MediaLive input.
    pub fn output_type(&self) -> ::std::option::Option<&crate::types::InputDeviceOutputType> {
        self.output_type.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeInputDeviceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeInputDeviceOutput {
    /// Creates a new builder-style object to manufacture [`DescribeInputDeviceOutput`](crate::operation::describe_input_device::DescribeInputDeviceOutput).
    pub fn builder() -> crate::operation::describe_input_device::builders::DescribeInputDeviceOutputBuilder {
        crate::operation::describe_input_device::builders::DescribeInputDeviceOutputBuilder::default()
    }
}

/// A builder for [`DescribeInputDeviceOutput`](crate::operation::describe_input_device::DescribeInputDeviceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeInputDeviceOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) connection_state: ::std::option::Option<crate::types::InputDeviceConnectionState>,
    pub(crate) device_settings_sync_state: ::std::option::Option<crate::types::DeviceSettingsSyncState>,
    pub(crate) device_update_status: ::std::option::Option<crate::types::DeviceUpdateStatus>,
    pub(crate) hd_device_settings: ::std::option::Option<crate::types::InputDeviceHdSettings>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) mac_address: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) network_settings: ::std::option::Option<crate::types::InputDeviceNetworkSettings>,
    pub(crate) serial_number: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::InputDeviceType>,
    pub(crate) uhd_device_settings: ::std::option::Option<crate::types::InputDeviceUhdSettings>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) availability_zone: ::std::option::Option<::std::string::String>,
    pub(crate) medialive_input_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) output_type: ::std::option::Option<crate::types::InputDeviceOutputType>,
    _request_id: Option<String>,
}
impl DescribeInputDeviceOutputBuilder {
    /// The unique ARN of the input device.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// The unique ARN of the input device.
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// The unique ARN of the input device.
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// The state of the connection between the input device and AWS.
    pub fn connection_state(mut self, input: crate::types::InputDeviceConnectionState) -> Self {
        self.connection_state = ::std::option::Option::Some(input);
        self
    }
    /// The state of the connection between the input device and AWS.
    pub fn set_connection_state(mut self, input: ::std::option::Option<crate::types::InputDeviceConnectionState>) -> Self {
        self.connection_state = input;
        self
    }
    /// The state of the connection between the input device and AWS.
    pub fn get_connection_state(&self) -> &::std::option::Option<crate::types::InputDeviceConnectionState> {
        &self.connection_state
    }
    /// The status of the action to synchronize the device configuration. If you change the configuration of the input device (for example, the maximum bitrate), MediaLive sends the new data to the device. The device might not update itself immediately. SYNCED means the device has updated its configuration. SYNCING means that it has not updated its configuration.
    pub fn device_settings_sync_state(mut self, input: crate::types::DeviceSettingsSyncState) -> Self {
        self.device_settings_sync_state = ::std::option::Option::Some(input);
        self
    }
    /// The status of the action to synchronize the device configuration. If you change the configuration of the input device (for example, the maximum bitrate), MediaLive sends the new data to the device. The device might not update itself immediately. SYNCED means the device has updated its configuration. SYNCING means that it has not updated its configuration.
    pub fn set_device_settings_sync_state(mut self, input: ::std::option::Option<crate::types::DeviceSettingsSyncState>) -> Self {
        self.device_settings_sync_state = input;
        self
    }
    /// The status of the action to synchronize the device configuration. If you change the configuration of the input device (for example, the maximum bitrate), MediaLive sends the new data to the device. The device might not update itself immediately. SYNCED means the device has updated its configuration. SYNCING means that it has not updated its configuration.
    pub fn get_device_settings_sync_state(&self) -> &::std::option::Option<crate::types::DeviceSettingsSyncState> {
        &self.device_settings_sync_state
    }
    /// The status of software on the input device.
    pub fn device_update_status(mut self, input: crate::types::DeviceUpdateStatus) -> Self {
        self.device_update_status = ::std::option::Option::Some(input);
        self
    }
    /// The status of software on the input device.
    pub fn set_device_update_status(mut self, input: ::std::option::Option<crate::types::DeviceUpdateStatus>) -> Self {
        self.device_update_status = input;
        self
    }
    /// The status of software on the input device.
    pub fn get_device_update_status(&self) -> &::std::option::Option<crate::types::DeviceUpdateStatus> {
        &self.device_update_status
    }
    /// Settings that describe an input device that is type HD.
    pub fn hd_device_settings(mut self, input: crate::types::InputDeviceHdSettings) -> Self {
        self.hd_device_settings = ::std::option::Option::Some(input);
        self
    }
    /// Settings that describe an input device that is type HD.
    pub fn set_hd_device_settings(mut self, input: ::std::option::Option<crate::types::InputDeviceHdSettings>) -> Self {
        self.hd_device_settings = input;
        self
    }
    /// Settings that describe an input device that is type HD.
    pub fn get_hd_device_settings(&self) -> &::std::option::Option<crate::types::InputDeviceHdSettings> {
        &self.hd_device_settings
    }
    /// The unique ID of the input device.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// The unique ID of the input device.
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// The unique ID of the input device.
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// The network MAC address of the input device.
    pub fn mac_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.mac_address = ::std::option::Option::Some(input.into());
        self
    }
    /// The network MAC address of the input device.
    pub fn set_mac_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.mac_address = input;
        self
    }
    /// The network MAC address of the input device.
    pub fn get_mac_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.mac_address
    }
    /// A name that you specify for the input device.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// A name that you specify for the input device.
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// A name that you specify for the input device.
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// The network settings for the input device.
    pub fn network_settings(mut self, input: crate::types::InputDeviceNetworkSettings) -> Self {
        self.network_settings = ::std::option::Option::Some(input);
        self
    }
    /// The network settings for the input device.
    pub fn set_network_settings(mut self, input: ::std::option::Option<crate::types::InputDeviceNetworkSettings>) -> Self {
        self.network_settings = input;
        self
    }
    /// The network settings for the input device.
    pub fn get_network_settings(&self) -> &::std::option::Option<crate::types::InputDeviceNetworkSettings> {
        &self.network_settings
    }
    /// The unique serial number of the input device.
    pub fn serial_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.serial_number = ::std::option::Option::Some(input.into());
        self
    }
    /// The unique serial number of the input device.
    pub fn set_serial_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.serial_number = input;
        self
    }
    /// The unique serial number of the input device.
    pub fn get_serial_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.serial_number
    }
    /// The type of the input device.
    pub fn r#type(mut self, input: crate::types::InputDeviceType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// The type of the input device.
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::InputDeviceType>) -> Self {
        self.r#type = input;
        self
    }
    /// The type of the input device.
    pub fn get_type(&self) -> &::std::option::Option<crate::types::InputDeviceType> {
        &self.r#type
    }
    /// Settings that describe an input device that is type UHD.
    pub fn uhd_device_settings(mut self, input: crate::types::InputDeviceUhdSettings) -> Self {
        self.uhd_device_settings = ::std::option::Option::Some(input);
        self
    }
    /// Settings that describe an input device that is type UHD.
    pub fn set_uhd_device_settings(mut self, input: ::std::option::Option<crate::types::InputDeviceUhdSettings>) -> Self {
        self.uhd_device_settings = input;
        self
    }
    /// Settings that describe an input device that is type UHD.
    pub fn get_uhd_device_settings(&self) -> &::std::option::Option<crate::types::InputDeviceUhdSettings> {
        &self.uhd_device_settings
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// A collection of key-value pairs.
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// A collection of key-value pairs.
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// A collection of key-value pairs.
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// The Availability Zone associated with this input device.
    pub fn availability_zone(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.availability_zone = ::std::option::Option::Some(input.into());
        self
    }
    /// The Availability Zone associated with this input device.
    pub fn set_availability_zone(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.availability_zone = input;
        self
    }
    /// The Availability Zone associated with this input device.
    pub fn get_availability_zone(&self) -> &::std::option::Option<::std::string::String> {
        &self.availability_zone
    }
    /// Appends an item to `medialive_input_arns`.
    ///
    /// To override the contents of this collection use [`set_medialive_input_arns`](Self::set_medialive_input_arns).
    ///
    /// An array of the ARNs for the MediaLive inputs attached to the device. Returned only if the outputType is MEDIALIVE_INPUT.
    pub fn medialive_input_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.medialive_input_arns.unwrap_or_default();
        v.push(input.into());
        self.medialive_input_arns = ::std::option::Option::Some(v);
        self
    }
    /// An array of the ARNs for the MediaLive inputs attached to the device. Returned only if the outputType is MEDIALIVE_INPUT.
    pub fn set_medialive_input_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.medialive_input_arns = input;
        self
    }
    /// An array of the ARNs for the MediaLive inputs attached to the device. Returned only if the outputType is MEDIALIVE_INPUT.
    pub fn get_medialive_input_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.medialive_input_arns
    }
    /// The output attachment type of the input device. Specifies MEDIACONNECT_FLOW if this device is the source for a MediaConnect flow. Specifies MEDIALIVE_INPUT if this device is the source for a MediaLive input.
    pub fn output_type(mut self, input: crate::types::InputDeviceOutputType) -> Self {
        self.output_type = ::std::option::Option::Some(input);
        self
    }
    /// The output attachment type of the input device. Specifies MEDIACONNECT_FLOW if this device is the source for a MediaConnect flow. Specifies MEDIALIVE_INPUT if this device is the source for a MediaLive input.
    pub fn set_output_type(mut self, input: ::std::option::Option<crate::types::InputDeviceOutputType>) -> Self {
        self.output_type = input;
        self
    }
    /// The output attachment type of the input device. Specifies MEDIACONNECT_FLOW if this device is the source for a MediaConnect flow. Specifies MEDIALIVE_INPUT if this device is the source for a MediaLive input.
    pub fn get_output_type(&self) -> &::std::option::Option<crate::types::InputDeviceOutputType> {
        &self.output_type
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeInputDeviceOutput`](crate::operation::describe_input_device::DescribeInputDeviceOutput).
    pub fn build(self) -> crate::operation::describe_input_device::DescribeInputDeviceOutput {
        crate::operation::describe_input_device::DescribeInputDeviceOutput {
            arn: self.arn,
            connection_state: self.connection_state,
            device_settings_sync_state: self.device_settings_sync_state,
            device_update_status: self.device_update_status,
            hd_device_settings: self.hd_device_settings,
            id: self.id,
            mac_address: self.mac_address,
            name: self.name,
            network_settings: self.network_settings,
            serial_number: self.serial_number,
            r#type: self.r#type,
            uhd_device_settings: self.uhd_device_settings,
            tags: self.tags,
            availability_zone: self.availability_zone,
            medialive_input_arns: self.medialive_input_arns,
            output_type: self.output_type,
            _request_id: self._request_id,
        }
    }
}
