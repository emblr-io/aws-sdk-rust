// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetVehicleOutput {
    /// <p>The ID of the vehicle.</p>
    pub vehicle_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the vehicle to retrieve information about.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of a vehicle model (model manifest) associated with the vehicle.</p>
    pub model_manifest_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of a decoder manifest associated with the vehicle.</p>
    pub decoder_manifest_arn: ::std::option::Option<::std::string::String>,
    /// <p>Static information about a vehicle in a key-value pair. For example:</p>
    /// <p><code>"engineType"</code> : <code>"1.3 L R2"</code></p>
    pub attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>State templates associated with the vehicle.</p>
    pub state_templates: ::std::option::Option<::std::vec::Vec<crate::types::StateTemplateAssociation>>,
    /// <p>The time the vehicle was created in seconds since epoch (January 1, 1970 at midnight UTC time).</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time the vehicle was last updated in seconds since epoch (January 1, 1970 at midnight UTC time).</p>
    pub last_modification_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl GetVehicleOutput {
    /// <p>The ID of the vehicle.</p>
    pub fn vehicle_name(&self) -> ::std::option::Option<&str> {
        self.vehicle_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the vehicle to retrieve information about.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The ARN of a vehicle model (model manifest) associated with the vehicle.</p>
    pub fn model_manifest_arn(&self) -> ::std::option::Option<&str> {
        self.model_manifest_arn.as_deref()
    }
    /// <p>The ARN of a decoder manifest associated with the vehicle.</p>
    pub fn decoder_manifest_arn(&self) -> ::std::option::Option<&str> {
        self.decoder_manifest_arn.as_deref()
    }
    /// <p>Static information about a vehicle in a key-value pair. For example:</p>
    /// <p><code>"engineType"</code> : <code>"1.3 L R2"</code></p>
    pub fn attributes(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.attributes.as_ref()
    }
    /// <p>State templates associated with the vehicle.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.state_templates.is_none()`.
    pub fn state_templates(&self) -> &[crate::types::StateTemplateAssociation] {
        self.state_templates.as_deref().unwrap_or_default()
    }
    /// <p>The time the vehicle was created in seconds since epoch (January 1, 1970 at midnight UTC time).</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>The time the vehicle was last updated in seconds since epoch (January 1, 1970 at midnight UTC time).</p>
    pub fn last_modification_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modification_time.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetVehicleOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetVehicleOutput {
    /// Creates a new builder-style object to manufacture [`GetVehicleOutput`](crate::operation::get_vehicle::GetVehicleOutput).
    pub fn builder() -> crate::operation::get_vehicle::builders::GetVehicleOutputBuilder {
        crate::operation::get_vehicle::builders::GetVehicleOutputBuilder::default()
    }
}

/// A builder for [`GetVehicleOutput`](crate::operation::get_vehicle::GetVehicleOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetVehicleOutputBuilder {
    pub(crate) vehicle_name: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) model_manifest_arn: ::std::option::Option<::std::string::String>,
    pub(crate) decoder_manifest_arn: ::std::option::Option<::std::string::String>,
    pub(crate) attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) state_templates: ::std::option::Option<::std::vec::Vec<crate::types::StateTemplateAssociation>>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modification_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl GetVehicleOutputBuilder {
    /// <p>The ID of the vehicle.</p>
    pub fn vehicle_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vehicle_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the vehicle.</p>
    pub fn set_vehicle_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vehicle_name = input;
        self
    }
    /// <p>The ID of the vehicle.</p>
    pub fn get_vehicle_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.vehicle_name
    }
    /// <p>The Amazon Resource Name (ARN) of the vehicle to retrieve information about.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the vehicle to retrieve information about.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the vehicle to retrieve information about.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The ARN of a vehicle model (model manifest) associated with the vehicle.</p>
    pub fn model_manifest_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_manifest_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of a vehicle model (model manifest) associated with the vehicle.</p>
    pub fn set_model_manifest_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_manifest_arn = input;
        self
    }
    /// <p>The ARN of a vehicle model (model manifest) associated with the vehicle.</p>
    pub fn get_model_manifest_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_manifest_arn
    }
    /// <p>The ARN of a decoder manifest associated with the vehicle.</p>
    pub fn decoder_manifest_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.decoder_manifest_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of a decoder manifest associated with the vehicle.</p>
    pub fn set_decoder_manifest_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.decoder_manifest_arn = input;
        self
    }
    /// <p>The ARN of a decoder manifest associated with the vehicle.</p>
    pub fn get_decoder_manifest_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.decoder_manifest_arn
    }
    /// Adds a key-value pair to `attributes`.
    ///
    /// To override the contents of this collection use [`set_attributes`](Self::set_attributes).
    ///
    /// <p>Static information about a vehicle in a key-value pair. For example:</p>
    /// <p><code>"engineType"</code> : <code>"1.3 L R2"</code></p>
    pub fn attributes(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.attributes.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.attributes = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Static information about a vehicle in a key-value pair. For example:</p>
    /// <p><code>"engineType"</code> : <code>"1.3 L R2"</code></p>
    pub fn set_attributes(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.attributes = input;
        self
    }
    /// <p>Static information about a vehicle in a key-value pair. For example:</p>
    /// <p><code>"engineType"</code> : <code>"1.3 L R2"</code></p>
    pub fn get_attributes(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.attributes
    }
    /// Appends an item to `state_templates`.
    ///
    /// To override the contents of this collection use [`set_state_templates`](Self::set_state_templates).
    ///
    /// <p>State templates associated with the vehicle.</p>
    pub fn state_templates(mut self, input: crate::types::StateTemplateAssociation) -> Self {
        let mut v = self.state_templates.unwrap_or_default();
        v.push(input);
        self.state_templates = ::std::option::Option::Some(v);
        self
    }
    /// <p>State templates associated with the vehicle.</p>
    pub fn set_state_templates(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::StateTemplateAssociation>>) -> Self {
        self.state_templates = input;
        self
    }
    /// <p>State templates associated with the vehicle.</p>
    pub fn get_state_templates(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StateTemplateAssociation>> {
        &self.state_templates
    }
    /// <p>The time the vehicle was created in seconds since epoch (January 1, 1970 at midnight UTC time).</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time the vehicle was created in seconds since epoch (January 1, 1970 at midnight UTC time).</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The time the vehicle was created in seconds since epoch (January 1, 1970 at midnight UTC time).</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>The time the vehicle was last updated in seconds since epoch (January 1, 1970 at midnight UTC time).</p>
    pub fn last_modification_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modification_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time the vehicle was last updated in seconds since epoch (January 1, 1970 at midnight UTC time).</p>
    pub fn set_last_modification_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modification_time = input;
        self
    }
    /// <p>The time the vehicle was last updated in seconds since epoch (January 1, 1970 at midnight UTC time).</p>
    pub fn get_last_modification_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modification_time
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetVehicleOutput`](crate::operation::get_vehicle::GetVehicleOutput).
    pub fn build(self) -> crate::operation::get_vehicle::GetVehicleOutput {
        crate::operation::get_vehicle::GetVehicleOutput {
            vehicle_name: self.vehicle_name,
            arn: self.arn,
            model_manifest_arn: self.model_manifest_arn,
            decoder_manifest_arn: self.decoder_manifest_arn,
            attributes: self.attributes,
            state_templates: self.state_templates,
            creation_time: self.creation_time,
            last_modification_time: self.last_modification_time,
            _request_id: self._request_id,
        }
    }
}
