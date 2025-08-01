// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSlotTypeOutput {
    /// <p>The name of the slot type.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A description of the slot type.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A list of <code>EnumerationValue</code> objects that defines the values that the slot type can take.</p>
    pub enumeration_values: ::std::option::Option<::std::vec::Vec<crate::types::EnumerationValue>>,
    /// <p>The date that the slot type was updated. When you create a resource, the creation date and last update date are the same.</p>
    pub last_updated_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date that the slot type was created.</p>
    pub created_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The version of the slot type.</p>
    pub version: ::std::option::Option<::std::string::String>,
    /// <p>Checksum of the <code>$LATEST</code> version of the slot type.</p>
    pub checksum: ::std::option::Option<::std::string::String>,
    /// <p>The strategy that Amazon Lex uses to determine the value of the slot. For more information, see <code>PutSlotType</code>.</p>
    pub value_selection_strategy: ::std::option::Option<crate::types::SlotValueSelectionStrategy>,
    /// <p>The built-in slot type used as a parent for the slot type.</p>
    pub parent_slot_type_signature: ::std::option::Option<::std::string::String>,
    /// <p>Configuration information that extends the parent built-in slot type.</p>
    pub slot_type_configurations: ::std::option::Option<::std::vec::Vec<crate::types::SlotTypeConfiguration>>,
    _request_id: Option<String>,
}
impl GetSlotTypeOutput {
    /// <p>The name of the slot type.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A description of the slot type.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>A list of <code>EnumerationValue</code> objects that defines the values that the slot type can take.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.enumeration_values.is_none()`.
    pub fn enumeration_values(&self) -> &[crate::types::EnumerationValue] {
        self.enumeration_values.as_deref().unwrap_or_default()
    }
    /// <p>The date that the slot type was updated. When you create a resource, the creation date and last update date are the same.</p>
    pub fn last_updated_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_date.as_ref()
    }
    /// <p>The date that the slot type was created.</p>
    pub fn created_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_date.as_ref()
    }
    /// <p>The version of the slot type.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
    /// <p>Checksum of the <code>$LATEST</code> version of the slot type.</p>
    pub fn checksum(&self) -> ::std::option::Option<&str> {
        self.checksum.as_deref()
    }
    /// <p>The strategy that Amazon Lex uses to determine the value of the slot. For more information, see <code>PutSlotType</code>.</p>
    pub fn value_selection_strategy(&self) -> ::std::option::Option<&crate::types::SlotValueSelectionStrategy> {
        self.value_selection_strategy.as_ref()
    }
    /// <p>The built-in slot type used as a parent for the slot type.</p>
    pub fn parent_slot_type_signature(&self) -> ::std::option::Option<&str> {
        self.parent_slot_type_signature.as_deref()
    }
    /// <p>Configuration information that extends the parent built-in slot type.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.slot_type_configurations.is_none()`.
    pub fn slot_type_configurations(&self) -> &[crate::types::SlotTypeConfiguration] {
        self.slot_type_configurations.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetSlotTypeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetSlotTypeOutput {
    /// Creates a new builder-style object to manufacture [`GetSlotTypeOutput`](crate::operation::get_slot_type::GetSlotTypeOutput).
    pub fn builder() -> crate::operation::get_slot_type::builders::GetSlotTypeOutputBuilder {
        crate::operation::get_slot_type::builders::GetSlotTypeOutputBuilder::default()
    }
}

/// A builder for [`GetSlotTypeOutput`](crate::operation::get_slot_type::GetSlotTypeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSlotTypeOutputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) enumeration_values: ::std::option::Option<::std::vec::Vec<crate::types::EnumerationValue>>,
    pub(crate) last_updated_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) created_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
    pub(crate) checksum: ::std::option::Option<::std::string::String>,
    pub(crate) value_selection_strategy: ::std::option::Option<crate::types::SlotValueSelectionStrategy>,
    pub(crate) parent_slot_type_signature: ::std::option::Option<::std::string::String>,
    pub(crate) slot_type_configurations: ::std::option::Option<::std::vec::Vec<crate::types::SlotTypeConfiguration>>,
    _request_id: Option<String>,
}
impl GetSlotTypeOutputBuilder {
    /// <p>The name of the slot type.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the slot type.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the slot type.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A description of the slot type.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the slot type.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the slot type.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `enumeration_values`.
    ///
    /// To override the contents of this collection use [`set_enumeration_values`](Self::set_enumeration_values).
    ///
    /// <p>A list of <code>EnumerationValue</code> objects that defines the values that the slot type can take.</p>
    pub fn enumeration_values(mut self, input: crate::types::EnumerationValue) -> Self {
        let mut v = self.enumeration_values.unwrap_or_default();
        v.push(input);
        self.enumeration_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>EnumerationValue</code> objects that defines the values that the slot type can take.</p>
    pub fn set_enumeration_values(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EnumerationValue>>) -> Self {
        self.enumeration_values = input;
        self
    }
    /// <p>A list of <code>EnumerationValue</code> objects that defines the values that the slot type can take.</p>
    pub fn get_enumeration_values(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EnumerationValue>> {
        &self.enumeration_values
    }
    /// <p>The date that the slot type was updated. When you create a resource, the creation date and last update date are the same.</p>
    pub fn last_updated_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date that the slot type was updated. When you create a resource, the creation date and last update date are the same.</p>
    pub fn set_last_updated_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_date = input;
        self
    }
    /// <p>The date that the slot type was updated. When you create a resource, the creation date and last update date are the same.</p>
    pub fn get_last_updated_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_date
    }
    /// <p>The date that the slot type was created.</p>
    pub fn created_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date that the slot type was created.</p>
    pub fn set_created_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_date = input;
        self
    }
    /// <p>The date that the slot type was created.</p>
    pub fn get_created_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_date
    }
    /// <p>The version of the slot type.</p>
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the slot type.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The version of the slot type.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// <p>Checksum of the <code>$LATEST</code> version of the slot type.</p>
    pub fn checksum(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.checksum = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Checksum of the <code>$LATEST</code> version of the slot type.</p>
    pub fn set_checksum(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.checksum = input;
        self
    }
    /// <p>Checksum of the <code>$LATEST</code> version of the slot type.</p>
    pub fn get_checksum(&self) -> &::std::option::Option<::std::string::String> {
        &self.checksum
    }
    /// <p>The strategy that Amazon Lex uses to determine the value of the slot. For more information, see <code>PutSlotType</code>.</p>
    pub fn value_selection_strategy(mut self, input: crate::types::SlotValueSelectionStrategy) -> Self {
        self.value_selection_strategy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The strategy that Amazon Lex uses to determine the value of the slot. For more information, see <code>PutSlotType</code>.</p>
    pub fn set_value_selection_strategy(mut self, input: ::std::option::Option<crate::types::SlotValueSelectionStrategy>) -> Self {
        self.value_selection_strategy = input;
        self
    }
    /// <p>The strategy that Amazon Lex uses to determine the value of the slot. For more information, see <code>PutSlotType</code>.</p>
    pub fn get_value_selection_strategy(&self) -> &::std::option::Option<crate::types::SlotValueSelectionStrategy> {
        &self.value_selection_strategy
    }
    /// <p>The built-in slot type used as a parent for the slot type.</p>
    pub fn parent_slot_type_signature(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parent_slot_type_signature = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The built-in slot type used as a parent for the slot type.</p>
    pub fn set_parent_slot_type_signature(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parent_slot_type_signature = input;
        self
    }
    /// <p>The built-in slot type used as a parent for the slot type.</p>
    pub fn get_parent_slot_type_signature(&self) -> &::std::option::Option<::std::string::String> {
        &self.parent_slot_type_signature
    }
    /// Appends an item to `slot_type_configurations`.
    ///
    /// To override the contents of this collection use [`set_slot_type_configurations`](Self::set_slot_type_configurations).
    ///
    /// <p>Configuration information that extends the parent built-in slot type.</p>
    pub fn slot_type_configurations(mut self, input: crate::types::SlotTypeConfiguration) -> Self {
        let mut v = self.slot_type_configurations.unwrap_or_default();
        v.push(input);
        self.slot_type_configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>Configuration information that extends the parent built-in slot type.</p>
    pub fn set_slot_type_configurations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SlotTypeConfiguration>>) -> Self {
        self.slot_type_configurations = input;
        self
    }
    /// <p>Configuration information that extends the parent built-in slot type.</p>
    pub fn get_slot_type_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SlotTypeConfiguration>> {
        &self.slot_type_configurations
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetSlotTypeOutput`](crate::operation::get_slot_type::GetSlotTypeOutput).
    pub fn build(self) -> crate::operation::get_slot_type::GetSlotTypeOutput {
        crate::operation::get_slot_type::GetSlotTypeOutput {
            name: self.name,
            description: self.description,
            enumeration_values: self.enumeration_values,
            last_updated_date: self.last_updated_date,
            created_date: self.created_date,
            version: self.version,
            checksum: self.checksum,
            value_selection_strategy: self.value_selection_strategy,
            parent_slot_type_signature: self.parent_slot_type_signature,
            slot_type_configurations: self.slot_type_configurations,
            _request_id: self._request_id,
        }
    }
}
