// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateManagedThingInput {
    /// <p>The type of device used. This will be the hub controller, cloud device, or AWS IoT device.</p>
    pub role: ::std::option::Option<crate::types::Role>,
    /// <p>Owner of the device, usually an indication of whom the device belongs to. This value should not contain personal identifiable information.</p>
    pub owner: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the credential for the managed thing.</p>
    pub credential_locker_id: ::std::option::Option<::std::string::String>,
    /// <p>The authentication material defining the device connectivity setup requests. The authentication materials used are the device bar code.</p>
    pub authentication_material: ::std::option::Option<::std::string::String>,
    /// <p>The type of authentication material used for device connectivity setup requests.</p>
    pub authentication_material_type: ::std::option::Option<crate::types::AuthMaterialType>,
    /// <p>The serial number of the device.</p>
    pub serial_number: ::std::option::Option<::std::string::String>,
    /// <p>The brand of the device.</p>
    pub brand: ::std::option::Option<::std::string::String>,
    /// <p>The model of the device.</p>
    pub model: ::std::option::Option<::std::string::String>,
    /// <p>The name of the managed thing representing the physical device.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A report of the capabilities for the managed thing.</p>
    pub capability_report: ::std::option::Option<crate::types::CapabilityReport>,
    /// <p>The capability schemas that define the functionality and features supported by the managed thing, including device capabilities and their associated properties.</p>
    pub capability_schemas: ::std::option::Option<::std::vec::Vec<crate::types::CapabilitySchemaItem>>,
    /// <p>The capabilities of the device such as light bulb.</p>
    pub capabilities: ::std::option::Option<::std::string::String>,
    /// <p>An idempotency token. If you retry a request that completed successfully initially using the same client token and parameters, then the retry attempt will succeed without performing any further actions.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The classification of the managed thing such as light bulb or thermostat.</p>
    pub classification: ::std::option::Option<::std::string::String>,
    /// <p>A set of key/value pairs that are used to manage the managed thing.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The metadata for the managed thing.</p><note>
    /// <p>The <code>managedThing</code> <code>metadata</code> parameter is used for associating attributes with a <code>managedThing</code> that can be used for grouping over-the-air (OTA) tasks. Name value pairs in <code>metadata</code> can be used in the <code>OtaTargetQueryString</code> parameter for the <code>CreateOtaTask</code> API operation.</p>
    /// </note>
    pub meta_data: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateManagedThingInput {
    /// <p>The type of device used. This will be the hub controller, cloud device, or AWS IoT device.</p>
    pub fn role(&self) -> ::std::option::Option<&crate::types::Role> {
        self.role.as_ref()
    }
    /// <p>Owner of the device, usually an indication of whom the device belongs to. This value should not contain personal identifiable information.</p>
    pub fn owner(&self) -> ::std::option::Option<&str> {
        self.owner.as_deref()
    }
    /// <p>The identifier of the credential for the managed thing.</p>
    pub fn credential_locker_id(&self) -> ::std::option::Option<&str> {
        self.credential_locker_id.as_deref()
    }
    /// <p>The authentication material defining the device connectivity setup requests. The authentication materials used are the device bar code.</p>
    pub fn authentication_material(&self) -> ::std::option::Option<&str> {
        self.authentication_material.as_deref()
    }
    /// <p>The type of authentication material used for device connectivity setup requests.</p>
    pub fn authentication_material_type(&self) -> ::std::option::Option<&crate::types::AuthMaterialType> {
        self.authentication_material_type.as_ref()
    }
    /// <p>The serial number of the device.</p>
    pub fn serial_number(&self) -> ::std::option::Option<&str> {
        self.serial_number.as_deref()
    }
    /// <p>The brand of the device.</p>
    pub fn brand(&self) -> ::std::option::Option<&str> {
        self.brand.as_deref()
    }
    /// <p>The model of the device.</p>
    pub fn model(&self) -> ::std::option::Option<&str> {
        self.model.as_deref()
    }
    /// <p>The name of the managed thing representing the physical device.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A report of the capabilities for the managed thing.</p>
    pub fn capability_report(&self) -> ::std::option::Option<&crate::types::CapabilityReport> {
        self.capability_report.as_ref()
    }
    /// <p>The capability schemas that define the functionality and features supported by the managed thing, including device capabilities and their associated properties.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.capability_schemas.is_none()`.
    pub fn capability_schemas(&self) -> &[crate::types::CapabilitySchemaItem] {
        self.capability_schemas.as_deref().unwrap_or_default()
    }
    /// <p>The capabilities of the device such as light bulb.</p>
    pub fn capabilities(&self) -> ::std::option::Option<&str> {
        self.capabilities.as_deref()
    }
    /// <p>An idempotency token. If you retry a request that completed successfully initially using the same client token and parameters, then the retry attempt will succeed without performing any further actions.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The classification of the managed thing such as light bulb or thermostat.</p>
    pub fn classification(&self) -> ::std::option::Option<&str> {
        self.classification.as_deref()
    }
    /// <p>A set of key/value pairs that are used to manage the managed thing.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The metadata for the managed thing.</p><note>
    /// <p>The <code>managedThing</code> <code>metadata</code> parameter is used for associating attributes with a <code>managedThing</code> that can be used for grouping over-the-air (OTA) tasks. Name value pairs in <code>metadata</code> can be used in the <code>OtaTargetQueryString</code> parameter for the <code>CreateOtaTask</code> API operation.</p>
    /// </note>
    pub fn meta_data(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.meta_data.as_ref()
    }
}
impl ::std::fmt::Debug for CreateManagedThingInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateManagedThingInput");
        formatter.field("role", &self.role);
        formatter.field("owner", &"*** Sensitive Data Redacted ***");
        formatter.field("credential_locker_id", &self.credential_locker_id);
        formatter.field("authentication_material", &"*** Sensitive Data Redacted ***");
        formatter.field("authentication_material_type", &self.authentication_material_type);
        formatter.field("serial_number", &"*** Sensitive Data Redacted ***");
        formatter.field("brand", &"*** Sensitive Data Redacted ***");
        formatter.field("model", &"*** Sensitive Data Redacted ***");
        formatter.field("name", &self.name);
        formatter.field("capability_report", &self.capability_report);
        formatter.field("capability_schemas", &self.capability_schemas);
        formatter.field("capabilities", &self.capabilities);
        formatter.field("client_token", &self.client_token);
        formatter.field("classification", &"*** Sensitive Data Redacted ***");
        formatter.field("tags", &"*** Sensitive Data Redacted ***");
        formatter.field("meta_data", &self.meta_data);
        formatter.finish()
    }
}
impl CreateManagedThingInput {
    /// Creates a new builder-style object to manufacture [`CreateManagedThingInput`](crate::operation::create_managed_thing::CreateManagedThingInput).
    pub fn builder() -> crate::operation::create_managed_thing::builders::CreateManagedThingInputBuilder {
        crate::operation::create_managed_thing::builders::CreateManagedThingInputBuilder::default()
    }
}

/// A builder for [`CreateManagedThingInput`](crate::operation::create_managed_thing::CreateManagedThingInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateManagedThingInputBuilder {
    pub(crate) role: ::std::option::Option<crate::types::Role>,
    pub(crate) owner: ::std::option::Option<::std::string::String>,
    pub(crate) credential_locker_id: ::std::option::Option<::std::string::String>,
    pub(crate) authentication_material: ::std::option::Option<::std::string::String>,
    pub(crate) authentication_material_type: ::std::option::Option<crate::types::AuthMaterialType>,
    pub(crate) serial_number: ::std::option::Option<::std::string::String>,
    pub(crate) brand: ::std::option::Option<::std::string::String>,
    pub(crate) model: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) capability_report: ::std::option::Option<crate::types::CapabilityReport>,
    pub(crate) capability_schemas: ::std::option::Option<::std::vec::Vec<crate::types::CapabilitySchemaItem>>,
    pub(crate) capabilities: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) classification: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) meta_data: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateManagedThingInputBuilder {
    /// <p>The type of device used. This will be the hub controller, cloud device, or AWS IoT device.</p>
    /// This field is required.
    pub fn role(mut self, input: crate::types::Role) -> Self {
        self.role = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of device used. This will be the hub controller, cloud device, or AWS IoT device.</p>
    pub fn set_role(mut self, input: ::std::option::Option<crate::types::Role>) -> Self {
        self.role = input;
        self
    }
    /// <p>The type of device used. This will be the hub controller, cloud device, or AWS IoT device.</p>
    pub fn get_role(&self) -> &::std::option::Option<crate::types::Role> {
        &self.role
    }
    /// <p>Owner of the device, usually an indication of whom the device belongs to. This value should not contain personal identifiable information.</p>
    pub fn owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Owner of the device, usually an indication of whom the device belongs to. This value should not contain personal identifiable information.</p>
    pub fn set_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owner = input;
        self
    }
    /// <p>Owner of the device, usually an indication of whom the device belongs to. This value should not contain personal identifiable information.</p>
    pub fn get_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.owner
    }
    /// <p>The identifier of the credential for the managed thing.</p>
    pub fn credential_locker_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.credential_locker_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the credential for the managed thing.</p>
    pub fn set_credential_locker_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.credential_locker_id = input;
        self
    }
    /// <p>The identifier of the credential for the managed thing.</p>
    pub fn get_credential_locker_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.credential_locker_id
    }
    /// <p>The authentication material defining the device connectivity setup requests. The authentication materials used are the device bar code.</p>
    /// This field is required.
    pub fn authentication_material(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.authentication_material = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The authentication material defining the device connectivity setup requests. The authentication materials used are the device bar code.</p>
    pub fn set_authentication_material(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.authentication_material = input;
        self
    }
    /// <p>The authentication material defining the device connectivity setup requests. The authentication materials used are the device bar code.</p>
    pub fn get_authentication_material(&self) -> &::std::option::Option<::std::string::String> {
        &self.authentication_material
    }
    /// <p>The type of authentication material used for device connectivity setup requests.</p>
    /// This field is required.
    pub fn authentication_material_type(mut self, input: crate::types::AuthMaterialType) -> Self {
        self.authentication_material_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of authentication material used for device connectivity setup requests.</p>
    pub fn set_authentication_material_type(mut self, input: ::std::option::Option<crate::types::AuthMaterialType>) -> Self {
        self.authentication_material_type = input;
        self
    }
    /// <p>The type of authentication material used for device connectivity setup requests.</p>
    pub fn get_authentication_material_type(&self) -> &::std::option::Option<crate::types::AuthMaterialType> {
        &self.authentication_material_type
    }
    /// <p>The serial number of the device.</p>
    pub fn serial_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.serial_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The serial number of the device.</p>
    pub fn set_serial_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.serial_number = input;
        self
    }
    /// <p>The serial number of the device.</p>
    pub fn get_serial_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.serial_number
    }
    /// <p>The brand of the device.</p>
    pub fn brand(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.brand = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The brand of the device.</p>
    pub fn set_brand(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.brand = input;
        self
    }
    /// <p>The brand of the device.</p>
    pub fn get_brand(&self) -> &::std::option::Option<::std::string::String> {
        &self.brand
    }
    /// <p>The model of the device.</p>
    pub fn model(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The model of the device.</p>
    pub fn set_model(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model = input;
        self
    }
    /// <p>The model of the device.</p>
    pub fn get_model(&self) -> &::std::option::Option<::std::string::String> {
        &self.model
    }
    /// <p>The name of the managed thing representing the physical device.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the managed thing representing the physical device.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the managed thing representing the physical device.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A report of the capabilities for the managed thing.</p>
    pub fn capability_report(mut self, input: crate::types::CapabilityReport) -> Self {
        self.capability_report = ::std::option::Option::Some(input);
        self
    }
    /// <p>A report of the capabilities for the managed thing.</p>
    pub fn set_capability_report(mut self, input: ::std::option::Option<crate::types::CapabilityReport>) -> Self {
        self.capability_report = input;
        self
    }
    /// <p>A report of the capabilities for the managed thing.</p>
    pub fn get_capability_report(&self) -> &::std::option::Option<crate::types::CapabilityReport> {
        &self.capability_report
    }
    /// Appends an item to `capability_schemas`.
    ///
    /// To override the contents of this collection use [`set_capability_schemas`](Self::set_capability_schemas).
    ///
    /// <p>The capability schemas that define the functionality and features supported by the managed thing, including device capabilities and their associated properties.</p>
    pub fn capability_schemas(mut self, input: crate::types::CapabilitySchemaItem) -> Self {
        let mut v = self.capability_schemas.unwrap_or_default();
        v.push(input);
        self.capability_schemas = ::std::option::Option::Some(v);
        self
    }
    /// <p>The capability schemas that define the functionality and features supported by the managed thing, including device capabilities and their associated properties.</p>
    pub fn set_capability_schemas(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CapabilitySchemaItem>>) -> Self {
        self.capability_schemas = input;
        self
    }
    /// <p>The capability schemas that define the functionality and features supported by the managed thing, including device capabilities and their associated properties.</p>
    pub fn get_capability_schemas(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CapabilitySchemaItem>> {
        &self.capability_schemas
    }
    /// <p>The capabilities of the device such as light bulb.</p>
    pub fn capabilities(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.capabilities = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The capabilities of the device such as light bulb.</p>
    pub fn set_capabilities(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.capabilities = input;
        self
    }
    /// <p>The capabilities of the device such as light bulb.</p>
    pub fn get_capabilities(&self) -> &::std::option::Option<::std::string::String> {
        &self.capabilities
    }
    /// <p>An idempotency token. If you retry a request that completed successfully initially using the same client token and parameters, then the retry attempt will succeed without performing any further actions.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An idempotency token. If you retry a request that completed successfully initially using the same client token and parameters, then the retry attempt will succeed without performing any further actions.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>An idempotency token. If you retry a request that completed successfully initially using the same client token and parameters, then the retry attempt will succeed without performing any further actions.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>The classification of the managed thing such as light bulb or thermostat.</p>
    pub fn classification(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.classification = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The classification of the managed thing such as light bulb or thermostat.</p>
    pub fn set_classification(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.classification = input;
        self
    }
    /// <p>The classification of the managed thing such as light bulb or thermostat.</p>
    pub fn get_classification(&self) -> &::std::option::Option<::std::string::String> {
        &self.classification
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A set of key/value pairs that are used to manage the managed thing.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A set of key/value pairs that are used to manage the managed thing.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A set of key/value pairs that are used to manage the managed thing.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Adds a key-value pair to `meta_data`.
    ///
    /// To override the contents of this collection use [`set_meta_data`](Self::set_meta_data).
    ///
    /// <p>The metadata for the managed thing.</p><note>
    /// <p>The <code>managedThing</code> <code>metadata</code> parameter is used for associating attributes with a <code>managedThing</code> that can be used for grouping over-the-air (OTA) tasks. Name value pairs in <code>metadata</code> can be used in the <code>OtaTargetQueryString</code> parameter for the <code>CreateOtaTask</code> API operation.</p>
    /// </note>
    pub fn meta_data(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.meta_data.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.meta_data = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The metadata for the managed thing.</p><note>
    /// <p>The <code>managedThing</code> <code>metadata</code> parameter is used for associating attributes with a <code>managedThing</code> that can be used for grouping over-the-air (OTA) tasks. Name value pairs in <code>metadata</code> can be used in the <code>OtaTargetQueryString</code> parameter for the <code>CreateOtaTask</code> API operation.</p>
    /// </note>
    pub fn set_meta_data(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.meta_data = input;
        self
    }
    /// <p>The metadata for the managed thing.</p><note>
    /// <p>The <code>managedThing</code> <code>metadata</code> parameter is used for associating attributes with a <code>managedThing</code> that can be used for grouping over-the-air (OTA) tasks. Name value pairs in <code>metadata</code> can be used in the <code>OtaTargetQueryString</code> parameter for the <code>CreateOtaTask</code> API operation.</p>
    /// </note>
    pub fn get_meta_data(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.meta_data
    }
    /// Consumes the builder and constructs a [`CreateManagedThingInput`](crate::operation::create_managed_thing::CreateManagedThingInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_managed_thing::CreateManagedThingInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_managed_thing::CreateManagedThingInput {
            role: self.role,
            owner: self.owner,
            credential_locker_id: self.credential_locker_id,
            authentication_material: self.authentication_material,
            authentication_material_type: self.authentication_material_type,
            serial_number: self.serial_number,
            brand: self.brand,
            model: self.model,
            name: self.name,
            capability_report: self.capability_report,
            capability_schemas: self.capability_schemas,
            capabilities: self.capabilities,
            client_token: self.client_token,
            classification: self.classification,
            tags: self.tags,
            meta_data: self.meta_data,
        })
    }
}
impl ::std::fmt::Debug for CreateManagedThingInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateManagedThingInputBuilder");
        formatter.field("role", &self.role);
        formatter.field("owner", &"*** Sensitive Data Redacted ***");
        formatter.field("credential_locker_id", &self.credential_locker_id);
        formatter.field("authentication_material", &"*** Sensitive Data Redacted ***");
        formatter.field("authentication_material_type", &self.authentication_material_type);
        formatter.field("serial_number", &"*** Sensitive Data Redacted ***");
        formatter.field("brand", &"*** Sensitive Data Redacted ***");
        formatter.field("model", &"*** Sensitive Data Redacted ***");
        formatter.field("name", &self.name);
        formatter.field("capability_report", &self.capability_report);
        formatter.field("capability_schemas", &self.capability_schemas);
        formatter.field("capabilities", &self.capabilities);
        formatter.field("client_token", &self.client_token);
        formatter.field("classification", &"*** Sensitive Data Redacted ***");
        formatter.field("tags", &"*** Sensitive Data Redacted ***");
        formatter.field("meta_data", &self.meta_data);
        formatter.finish()
    }
}
