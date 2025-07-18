// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateSlotTypeInput {
    /// <p>The unique identifier of the slot type to update.</p>
    pub slot_type_id: ::std::option::Option<::std::string::String>,
    /// <p>The new name of the slot type.</p>
    pub slot_type_name: ::std::option::Option<::std::string::String>,
    /// <p>The new description of the slot type.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A new list of values and their optional synonyms that define the values that the slot type can take.</p>
    pub slot_type_values: ::std::option::Option<::std::vec::Vec<crate::types::SlotTypeValue>>,
    /// <p>The strategy that Amazon Lex should use when deciding on a value from the list of slot type values.</p>
    pub value_selection_setting: ::std::option::Option<crate::types::SlotValueSelectionSetting>,
    /// <p>The new built-in slot type that should be used as the parent of this slot type.</p>
    pub parent_slot_type_signature: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the bot that contains the slot type.</p>
    pub bot_id: ::std::option::Option<::std::string::String>,
    /// <p>The version of the bot that contains the slot type. Must be <code>DRAFT</code>.</p>
    pub bot_version: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the language and locale that contains the slot type. The string must match one of the supported locales. For more information, see <a href="https://docs.aws.amazon.com/lexv2/latest/dg/how-languages.html">Supported languages</a>.</p>
    pub locale_id: ::std::option::Option<::std::string::String>,
    /// <p>Provides information about the external source of the slot type's definition.</p>
    pub external_source_setting: ::std::option::Option<crate::types::ExternalSourceSetting>,
    /// <p>Specifications for a composite slot type.</p>
    pub composite_slot_type_setting: ::std::option::Option<crate::types::CompositeSlotTypeSetting>,
}
impl UpdateSlotTypeInput {
    /// <p>The unique identifier of the slot type to update.</p>
    pub fn slot_type_id(&self) -> ::std::option::Option<&str> {
        self.slot_type_id.as_deref()
    }
    /// <p>The new name of the slot type.</p>
    pub fn slot_type_name(&self) -> ::std::option::Option<&str> {
        self.slot_type_name.as_deref()
    }
    /// <p>The new description of the slot type.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>A new list of values and their optional synonyms that define the values that the slot type can take.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.slot_type_values.is_none()`.
    pub fn slot_type_values(&self) -> &[crate::types::SlotTypeValue] {
        self.slot_type_values.as_deref().unwrap_or_default()
    }
    /// <p>The strategy that Amazon Lex should use when deciding on a value from the list of slot type values.</p>
    pub fn value_selection_setting(&self) -> ::std::option::Option<&crate::types::SlotValueSelectionSetting> {
        self.value_selection_setting.as_ref()
    }
    /// <p>The new built-in slot type that should be used as the parent of this slot type.</p>
    pub fn parent_slot_type_signature(&self) -> ::std::option::Option<&str> {
        self.parent_slot_type_signature.as_deref()
    }
    /// <p>The identifier of the bot that contains the slot type.</p>
    pub fn bot_id(&self) -> ::std::option::Option<&str> {
        self.bot_id.as_deref()
    }
    /// <p>The version of the bot that contains the slot type. Must be <code>DRAFT</code>.</p>
    pub fn bot_version(&self) -> ::std::option::Option<&str> {
        self.bot_version.as_deref()
    }
    /// <p>The identifier of the language and locale that contains the slot type. The string must match one of the supported locales. For more information, see <a href="https://docs.aws.amazon.com/lexv2/latest/dg/how-languages.html">Supported languages</a>.</p>
    pub fn locale_id(&self) -> ::std::option::Option<&str> {
        self.locale_id.as_deref()
    }
    /// <p>Provides information about the external source of the slot type's definition.</p>
    pub fn external_source_setting(&self) -> ::std::option::Option<&crate::types::ExternalSourceSetting> {
        self.external_source_setting.as_ref()
    }
    /// <p>Specifications for a composite slot type.</p>
    pub fn composite_slot_type_setting(&self) -> ::std::option::Option<&crate::types::CompositeSlotTypeSetting> {
        self.composite_slot_type_setting.as_ref()
    }
}
impl UpdateSlotTypeInput {
    /// Creates a new builder-style object to manufacture [`UpdateSlotTypeInput`](crate::operation::update_slot_type::UpdateSlotTypeInput).
    pub fn builder() -> crate::operation::update_slot_type::builders::UpdateSlotTypeInputBuilder {
        crate::operation::update_slot_type::builders::UpdateSlotTypeInputBuilder::default()
    }
}

/// A builder for [`UpdateSlotTypeInput`](crate::operation::update_slot_type::UpdateSlotTypeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateSlotTypeInputBuilder {
    pub(crate) slot_type_id: ::std::option::Option<::std::string::String>,
    pub(crate) slot_type_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) slot_type_values: ::std::option::Option<::std::vec::Vec<crate::types::SlotTypeValue>>,
    pub(crate) value_selection_setting: ::std::option::Option<crate::types::SlotValueSelectionSetting>,
    pub(crate) parent_slot_type_signature: ::std::option::Option<::std::string::String>,
    pub(crate) bot_id: ::std::option::Option<::std::string::String>,
    pub(crate) bot_version: ::std::option::Option<::std::string::String>,
    pub(crate) locale_id: ::std::option::Option<::std::string::String>,
    pub(crate) external_source_setting: ::std::option::Option<crate::types::ExternalSourceSetting>,
    pub(crate) composite_slot_type_setting: ::std::option::Option<crate::types::CompositeSlotTypeSetting>,
}
impl UpdateSlotTypeInputBuilder {
    /// <p>The unique identifier of the slot type to update.</p>
    /// This field is required.
    pub fn slot_type_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.slot_type_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the slot type to update.</p>
    pub fn set_slot_type_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.slot_type_id = input;
        self
    }
    /// <p>The unique identifier of the slot type to update.</p>
    pub fn get_slot_type_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.slot_type_id
    }
    /// <p>The new name of the slot type.</p>
    /// This field is required.
    pub fn slot_type_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.slot_type_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The new name of the slot type.</p>
    pub fn set_slot_type_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.slot_type_name = input;
        self
    }
    /// <p>The new name of the slot type.</p>
    pub fn get_slot_type_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.slot_type_name
    }
    /// <p>The new description of the slot type.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The new description of the slot type.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The new description of the slot type.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `slot_type_values`.
    ///
    /// To override the contents of this collection use [`set_slot_type_values`](Self::set_slot_type_values).
    ///
    /// <p>A new list of values and their optional synonyms that define the values that the slot type can take.</p>
    pub fn slot_type_values(mut self, input: crate::types::SlotTypeValue) -> Self {
        let mut v = self.slot_type_values.unwrap_or_default();
        v.push(input);
        self.slot_type_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>A new list of values and their optional synonyms that define the values that the slot type can take.</p>
    pub fn set_slot_type_values(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SlotTypeValue>>) -> Self {
        self.slot_type_values = input;
        self
    }
    /// <p>A new list of values and their optional synonyms that define the values that the slot type can take.</p>
    pub fn get_slot_type_values(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SlotTypeValue>> {
        &self.slot_type_values
    }
    /// <p>The strategy that Amazon Lex should use when deciding on a value from the list of slot type values.</p>
    pub fn value_selection_setting(mut self, input: crate::types::SlotValueSelectionSetting) -> Self {
        self.value_selection_setting = ::std::option::Option::Some(input);
        self
    }
    /// <p>The strategy that Amazon Lex should use when deciding on a value from the list of slot type values.</p>
    pub fn set_value_selection_setting(mut self, input: ::std::option::Option<crate::types::SlotValueSelectionSetting>) -> Self {
        self.value_selection_setting = input;
        self
    }
    /// <p>The strategy that Amazon Lex should use when deciding on a value from the list of slot type values.</p>
    pub fn get_value_selection_setting(&self) -> &::std::option::Option<crate::types::SlotValueSelectionSetting> {
        &self.value_selection_setting
    }
    /// <p>The new built-in slot type that should be used as the parent of this slot type.</p>
    pub fn parent_slot_type_signature(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parent_slot_type_signature = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The new built-in slot type that should be used as the parent of this slot type.</p>
    pub fn set_parent_slot_type_signature(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parent_slot_type_signature = input;
        self
    }
    /// <p>The new built-in slot type that should be used as the parent of this slot type.</p>
    pub fn get_parent_slot_type_signature(&self) -> &::std::option::Option<::std::string::String> {
        &self.parent_slot_type_signature
    }
    /// <p>The identifier of the bot that contains the slot type.</p>
    /// This field is required.
    pub fn bot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the bot that contains the slot type.</p>
    pub fn set_bot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_id = input;
        self
    }
    /// <p>The identifier of the bot that contains the slot type.</p>
    pub fn get_bot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_id
    }
    /// <p>The version of the bot that contains the slot type. Must be <code>DRAFT</code>.</p>
    /// This field is required.
    pub fn bot_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the bot that contains the slot type. Must be <code>DRAFT</code>.</p>
    pub fn set_bot_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_version = input;
        self
    }
    /// <p>The version of the bot that contains the slot type. Must be <code>DRAFT</code>.</p>
    pub fn get_bot_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_version
    }
    /// <p>The identifier of the language and locale that contains the slot type. The string must match one of the supported locales. For more information, see <a href="https://docs.aws.amazon.com/lexv2/latest/dg/how-languages.html">Supported languages</a>.</p>
    /// This field is required.
    pub fn locale_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.locale_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the language and locale that contains the slot type. The string must match one of the supported locales. For more information, see <a href="https://docs.aws.amazon.com/lexv2/latest/dg/how-languages.html">Supported languages</a>.</p>
    pub fn set_locale_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.locale_id = input;
        self
    }
    /// <p>The identifier of the language and locale that contains the slot type. The string must match one of the supported locales. For more information, see <a href="https://docs.aws.amazon.com/lexv2/latest/dg/how-languages.html">Supported languages</a>.</p>
    pub fn get_locale_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.locale_id
    }
    /// <p>Provides information about the external source of the slot type's definition.</p>
    pub fn external_source_setting(mut self, input: crate::types::ExternalSourceSetting) -> Self {
        self.external_source_setting = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides information about the external source of the slot type's definition.</p>
    pub fn set_external_source_setting(mut self, input: ::std::option::Option<crate::types::ExternalSourceSetting>) -> Self {
        self.external_source_setting = input;
        self
    }
    /// <p>Provides information about the external source of the slot type's definition.</p>
    pub fn get_external_source_setting(&self) -> &::std::option::Option<crate::types::ExternalSourceSetting> {
        &self.external_source_setting
    }
    /// <p>Specifications for a composite slot type.</p>
    pub fn composite_slot_type_setting(mut self, input: crate::types::CompositeSlotTypeSetting) -> Self {
        self.composite_slot_type_setting = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifications for a composite slot type.</p>
    pub fn set_composite_slot_type_setting(mut self, input: ::std::option::Option<crate::types::CompositeSlotTypeSetting>) -> Self {
        self.composite_slot_type_setting = input;
        self
    }
    /// <p>Specifications for a composite slot type.</p>
    pub fn get_composite_slot_type_setting(&self) -> &::std::option::Option<crate::types::CompositeSlotTypeSetting> {
        &self.composite_slot_type_setting
    }
    /// Consumes the builder and constructs a [`UpdateSlotTypeInput`](crate::operation::update_slot_type::UpdateSlotTypeInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_slot_type::UpdateSlotTypeInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_slot_type::UpdateSlotTypeInput {
            slot_type_id: self.slot_type_id,
            slot_type_name: self.slot_type_name,
            description: self.description,
            slot_type_values: self.slot_type_values,
            value_selection_setting: self.value_selection_setting,
            parent_slot_type_signature: self.parent_slot_type_signature,
            bot_id: self.bot_id,
            bot_version: self.bot_version,
            locale_id: self.locale_id,
            external_source_setting: self.external_source_setting,
            composite_slot_type_setting: self.composite_slot_type_setting,
        })
    }
}
