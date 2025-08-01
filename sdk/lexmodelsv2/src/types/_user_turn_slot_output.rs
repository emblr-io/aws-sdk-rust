// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about a slot output by the test set execution.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UserTurnSlotOutput {
    /// <p>The value output by the slot recognition.</p>
    pub value: ::std::option::Option<::std::string::String>,
    /// <p>Values that are output by the slot recognition.</p>
    pub values: ::std::option::Option<::std::vec::Vec<crate::types::UserTurnSlotOutput>>,
    /// <p>A list of items mapping the name of the subslots to information about those subslots.</p>
    pub sub_slots: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::UserTurnSlotOutput>>,
}
impl UserTurnSlotOutput {
    /// <p>The value output by the slot recognition.</p>
    pub fn value(&self) -> ::std::option::Option<&str> {
        self.value.as_deref()
    }
    /// <p>Values that are output by the slot recognition.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.values.is_none()`.
    pub fn values(&self) -> &[crate::types::UserTurnSlotOutput] {
        self.values.as_deref().unwrap_or_default()
    }
    /// <p>A list of items mapping the name of the subslots to information about those subslots.</p>
    pub fn sub_slots(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::UserTurnSlotOutput>> {
        self.sub_slots.as_ref()
    }
}
impl UserTurnSlotOutput {
    /// Creates a new builder-style object to manufacture [`UserTurnSlotOutput`](crate::types::UserTurnSlotOutput).
    pub fn builder() -> crate::types::builders::UserTurnSlotOutputBuilder {
        crate::types::builders::UserTurnSlotOutputBuilder::default()
    }
}

/// A builder for [`UserTurnSlotOutput`](crate::types::UserTurnSlotOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UserTurnSlotOutputBuilder {
    pub(crate) value: ::std::option::Option<::std::string::String>,
    pub(crate) values: ::std::option::Option<::std::vec::Vec<crate::types::UserTurnSlotOutput>>,
    pub(crate) sub_slots: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::UserTurnSlotOutput>>,
}
impl UserTurnSlotOutputBuilder {
    /// <p>The value output by the slot recognition.</p>
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value output by the slot recognition.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value output by the slot recognition.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// Appends an item to `values`.
    ///
    /// To override the contents of this collection use [`set_values`](Self::set_values).
    ///
    /// <p>Values that are output by the slot recognition.</p>
    pub fn values(mut self, input: crate::types::UserTurnSlotOutput) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input);
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>Values that are output by the slot recognition.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UserTurnSlotOutput>>) -> Self {
        self.values = input;
        self
    }
    /// <p>Values that are output by the slot recognition.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UserTurnSlotOutput>> {
        &self.values
    }
    /// Adds a key-value pair to `sub_slots`.
    ///
    /// To override the contents of this collection use [`set_sub_slots`](Self::set_sub_slots).
    ///
    /// <p>A list of items mapping the name of the subslots to information about those subslots.</p>
    pub fn sub_slots(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::UserTurnSlotOutput) -> Self {
        let mut hash_map = self.sub_slots.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.sub_slots = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A list of items mapping the name of the subslots to information about those subslots.</p>
    pub fn set_sub_slots(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::UserTurnSlotOutput>>,
    ) -> Self {
        self.sub_slots = input;
        self
    }
    /// <p>A list of items mapping the name of the subslots to information about those subslots.</p>
    pub fn get_sub_slots(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::UserTurnSlotOutput>> {
        &self.sub_slots
    }
    /// Consumes the builder and constructs a [`UserTurnSlotOutput`](crate::types::UserTurnSlotOutput).
    pub fn build(self) -> crate::types::UserTurnSlotOutput {
        crate::types::UserTurnSlotOutput {
            value: self.value,
            values: self.values,
            sub_slots: self.sub_slots,
        }
    }
}
