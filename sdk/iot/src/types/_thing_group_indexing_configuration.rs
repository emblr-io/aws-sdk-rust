// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Thing group indexing configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ThingGroupIndexingConfiguration {
    /// <p>Thing group indexing mode.</p>
    pub thing_group_indexing_mode: crate::types::ThingGroupIndexingMode,
    /// <p>Contains fields that are indexed and whose types are already known by the Fleet Indexing service. This is an optional field. For more information, see <a href="https://docs.aws.amazon.com/iot/latest/developerguide/managing-fleet-index.html#managed-field">Managed fields</a> in the <i>Amazon Web Services IoT Core Developer Guide</i>.</p><note>
    /// <p>You can't modify managed fields by updating fleet indexing configuration.</p>
    /// </note>
    pub managed_fields: ::std::option::Option<::std::vec::Vec<crate::types::Field>>,
    /// <p>A list of thing group fields to index. This list cannot contain any managed fields. Use the GetIndexingConfiguration API to get a list of managed fields.</p>
    /// <p>Contains custom field names and their data type.</p>
    pub custom_fields: ::std::option::Option<::std::vec::Vec<crate::types::Field>>,
}
impl ThingGroupIndexingConfiguration {
    /// <p>Thing group indexing mode.</p>
    pub fn thing_group_indexing_mode(&self) -> &crate::types::ThingGroupIndexingMode {
        &self.thing_group_indexing_mode
    }
    /// <p>Contains fields that are indexed and whose types are already known by the Fleet Indexing service. This is an optional field. For more information, see <a href="https://docs.aws.amazon.com/iot/latest/developerguide/managing-fleet-index.html#managed-field">Managed fields</a> in the <i>Amazon Web Services IoT Core Developer Guide</i>.</p><note>
    /// <p>You can't modify managed fields by updating fleet indexing configuration.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.managed_fields.is_none()`.
    pub fn managed_fields(&self) -> &[crate::types::Field] {
        self.managed_fields.as_deref().unwrap_or_default()
    }
    /// <p>A list of thing group fields to index. This list cannot contain any managed fields. Use the GetIndexingConfiguration API to get a list of managed fields.</p>
    /// <p>Contains custom field names and their data type.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.custom_fields.is_none()`.
    pub fn custom_fields(&self) -> &[crate::types::Field] {
        self.custom_fields.as_deref().unwrap_or_default()
    }
}
impl ThingGroupIndexingConfiguration {
    /// Creates a new builder-style object to manufacture [`ThingGroupIndexingConfiguration`](crate::types::ThingGroupIndexingConfiguration).
    pub fn builder() -> crate::types::builders::ThingGroupIndexingConfigurationBuilder {
        crate::types::builders::ThingGroupIndexingConfigurationBuilder::default()
    }
}

/// A builder for [`ThingGroupIndexingConfiguration`](crate::types::ThingGroupIndexingConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ThingGroupIndexingConfigurationBuilder {
    pub(crate) thing_group_indexing_mode: ::std::option::Option<crate::types::ThingGroupIndexingMode>,
    pub(crate) managed_fields: ::std::option::Option<::std::vec::Vec<crate::types::Field>>,
    pub(crate) custom_fields: ::std::option::Option<::std::vec::Vec<crate::types::Field>>,
}
impl ThingGroupIndexingConfigurationBuilder {
    /// <p>Thing group indexing mode.</p>
    /// This field is required.
    pub fn thing_group_indexing_mode(mut self, input: crate::types::ThingGroupIndexingMode) -> Self {
        self.thing_group_indexing_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>Thing group indexing mode.</p>
    pub fn set_thing_group_indexing_mode(mut self, input: ::std::option::Option<crate::types::ThingGroupIndexingMode>) -> Self {
        self.thing_group_indexing_mode = input;
        self
    }
    /// <p>Thing group indexing mode.</p>
    pub fn get_thing_group_indexing_mode(&self) -> &::std::option::Option<crate::types::ThingGroupIndexingMode> {
        &self.thing_group_indexing_mode
    }
    /// Appends an item to `managed_fields`.
    ///
    /// To override the contents of this collection use [`set_managed_fields`](Self::set_managed_fields).
    ///
    /// <p>Contains fields that are indexed and whose types are already known by the Fleet Indexing service. This is an optional field. For more information, see <a href="https://docs.aws.amazon.com/iot/latest/developerguide/managing-fleet-index.html#managed-field">Managed fields</a> in the <i>Amazon Web Services IoT Core Developer Guide</i>.</p><note>
    /// <p>You can't modify managed fields by updating fleet indexing configuration.</p>
    /// </note>
    pub fn managed_fields(mut self, input: crate::types::Field) -> Self {
        let mut v = self.managed_fields.unwrap_or_default();
        v.push(input);
        self.managed_fields = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains fields that are indexed and whose types are already known by the Fleet Indexing service. This is an optional field. For more information, see <a href="https://docs.aws.amazon.com/iot/latest/developerguide/managing-fleet-index.html#managed-field">Managed fields</a> in the <i>Amazon Web Services IoT Core Developer Guide</i>.</p><note>
    /// <p>You can't modify managed fields by updating fleet indexing configuration.</p>
    /// </note>
    pub fn set_managed_fields(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Field>>) -> Self {
        self.managed_fields = input;
        self
    }
    /// <p>Contains fields that are indexed and whose types are already known by the Fleet Indexing service. This is an optional field. For more information, see <a href="https://docs.aws.amazon.com/iot/latest/developerguide/managing-fleet-index.html#managed-field">Managed fields</a> in the <i>Amazon Web Services IoT Core Developer Guide</i>.</p><note>
    /// <p>You can't modify managed fields by updating fleet indexing configuration.</p>
    /// </note>
    pub fn get_managed_fields(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Field>> {
        &self.managed_fields
    }
    /// Appends an item to `custom_fields`.
    ///
    /// To override the contents of this collection use [`set_custom_fields`](Self::set_custom_fields).
    ///
    /// <p>A list of thing group fields to index. This list cannot contain any managed fields. Use the GetIndexingConfiguration API to get a list of managed fields.</p>
    /// <p>Contains custom field names and their data type.</p>
    pub fn custom_fields(mut self, input: crate::types::Field) -> Self {
        let mut v = self.custom_fields.unwrap_or_default();
        v.push(input);
        self.custom_fields = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of thing group fields to index. This list cannot contain any managed fields. Use the GetIndexingConfiguration API to get a list of managed fields.</p>
    /// <p>Contains custom field names and their data type.</p>
    pub fn set_custom_fields(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Field>>) -> Self {
        self.custom_fields = input;
        self
    }
    /// <p>A list of thing group fields to index. This list cannot contain any managed fields. Use the GetIndexingConfiguration API to get a list of managed fields.</p>
    /// <p>Contains custom field names and their data type.</p>
    pub fn get_custom_fields(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Field>> {
        &self.custom_fields
    }
    /// Consumes the builder and constructs a [`ThingGroupIndexingConfiguration`](crate::types::ThingGroupIndexingConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`thing_group_indexing_mode`](crate::types::builders::ThingGroupIndexingConfigurationBuilder::thing_group_indexing_mode)
    pub fn build(self) -> ::std::result::Result<crate::types::ThingGroupIndexingConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ThingGroupIndexingConfiguration {
            thing_group_indexing_mode: self.thing_group_indexing_mode.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "thing_group_indexing_mode",
                    "thing_group_indexing_mode was not specified but it is required when building ThingGroupIndexingConfiguration",
                )
            })?,
            managed_fields: self.managed_fields,
            custom_fields: self.custom_fields,
        })
    }
}
