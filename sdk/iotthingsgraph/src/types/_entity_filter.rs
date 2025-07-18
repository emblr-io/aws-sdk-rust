// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that filters an entity search. Multiple filters function as OR criteria in the search. For example a search that includes a <code>NAMESPACE</code> and a <code>REFERENCED_ENTITY_ID</code> filter searches for entities in the specified namespace that use the entity specified by the value of <code>REFERENCED_ENTITY_ID</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EntityFilter {
    /// <p>The name of the entity search filter field. <code>REFERENCED_ENTITY_ID</code> filters on entities that are used by the entity in the result set. For example, you can filter on the ID of a property that is used in a state.</p>
    pub name: ::std::option::Option<crate::types::EntityFilterName>,
    /// <p>An array of string values for the search filter field. Multiple values function as AND criteria in the search.</p>
    pub value: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl EntityFilter {
    /// <p>The name of the entity search filter field. <code>REFERENCED_ENTITY_ID</code> filters on entities that are used by the entity in the result set. For example, you can filter on the ID of a property that is used in a state.</p>
    pub fn name(&self) -> ::std::option::Option<&crate::types::EntityFilterName> {
        self.name.as_ref()
    }
    /// <p>An array of string values for the search filter field. Multiple values function as AND criteria in the search.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.value.is_none()`.
    pub fn value(&self) -> &[::std::string::String] {
        self.value.as_deref().unwrap_or_default()
    }
}
impl EntityFilter {
    /// Creates a new builder-style object to manufacture [`EntityFilter`](crate::types::EntityFilter).
    pub fn builder() -> crate::types::builders::EntityFilterBuilder {
        crate::types::builders::EntityFilterBuilder::default()
    }
}

/// A builder for [`EntityFilter`](crate::types::EntityFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EntityFilterBuilder {
    pub(crate) name: ::std::option::Option<crate::types::EntityFilterName>,
    pub(crate) value: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl EntityFilterBuilder {
    /// <p>The name of the entity search filter field. <code>REFERENCED_ENTITY_ID</code> filters on entities that are used by the entity in the result set. For example, you can filter on the ID of a property that is used in a state.</p>
    pub fn name(mut self, input: crate::types::EntityFilterName) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the entity search filter field. <code>REFERENCED_ENTITY_ID</code> filters on entities that are used by the entity in the result set. For example, you can filter on the ID of a property that is used in a state.</p>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::EntityFilterName>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the entity search filter field. <code>REFERENCED_ENTITY_ID</code> filters on entities that are used by the entity in the result set. For example, you can filter on the ID of a property that is used in a state.</p>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::EntityFilterName> {
        &self.name
    }
    /// Appends an item to `value`.
    ///
    /// To override the contents of this collection use [`set_value`](Self::set_value).
    ///
    /// <p>An array of string values for the search filter field. Multiple values function as AND criteria in the search.</p>
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.value.unwrap_or_default();
        v.push(input.into());
        self.value = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of string values for the search filter field. Multiple values function as AND criteria in the search.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.value = input;
        self
    }
    /// <p>An array of string values for the search filter field. Multiple values function as AND criteria in the search.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.value
    }
    /// Consumes the builder and constructs a [`EntityFilter`](crate::types::EntityFilter).
    pub fn build(self) -> crate::types::EntityFilter {
        crate::types::EntityFilter {
            name: self.name,
            value: self.value,
        }
    }
}
