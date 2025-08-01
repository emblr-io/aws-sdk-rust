// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutEventConfigurationInput {
    /// <p>The Amazon Resource Name (ARN) or ID suffix of the ARN of the event data store for which you want to update event configuration settings.</p>
    pub event_data_store: ::std::option::Option<::std::string::String>,
    /// <p>The maximum allowed size for events to be stored in the specified event data store. If you are using context key selectors, MaxEventSize must be set to Large.</p>
    pub max_event_size: ::std::option::Option<crate::types::MaxEventSize>,
    /// <p>A list of context key selectors that will be included to provide enriched event data.</p>
    pub context_key_selectors: ::std::option::Option<::std::vec::Vec<crate::types::ContextKeySelector>>,
}
impl PutEventConfigurationInput {
    /// <p>The Amazon Resource Name (ARN) or ID suffix of the ARN of the event data store for which you want to update event configuration settings.</p>
    pub fn event_data_store(&self) -> ::std::option::Option<&str> {
        self.event_data_store.as_deref()
    }
    /// <p>The maximum allowed size for events to be stored in the specified event data store. If you are using context key selectors, MaxEventSize must be set to Large.</p>
    pub fn max_event_size(&self) -> ::std::option::Option<&crate::types::MaxEventSize> {
        self.max_event_size.as_ref()
    }
    /// <p>A list of context key selectors that will be included to provide enriched event data.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.context_key_selectors.is_none()`.
    pub fn context_key_selectors(&self) -> &[crate::types::ContextKeySelector] {
        self.context_key_selectors.as_deref().unwrap_or_default()
    }
}
impl PutEventConfigurationInput {
    /// Creates a new builder-style object to manufacture [`PutEventConfigurationInput`](crate::operation::put_event_configuration::PutEventConfigurationInput).
    pub fn builder() -> crate::operation::put_event_configuration::builders::PutEventConfigurationInputBuilder {
        crate::operation::put_event_configuration::builders::PutEventConfigurationInputBuilder::default()
    }
}

/// A builder for [`PutEventConfigurationInput`](crate::operation::put_event_configuration::PutEventConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutEventConfigurationInputBuilder {
    pub(crate) event_data_store: ::std::option::Option<::std::string::String>,
    pub(crate) max_event_size: ::std::option::Option<crate::types::MaxEventSize>,
    pub(crate) context_key_selectors: ::std::option::Option<::std::vec::Vec<crate::types::ContextKeySelector>>,
}
impl PutEventConfigurationInputBuilder {
    /// <p>The Amazon Resource Name (ARN) or ID suffix of the ARN of the event data store for which you want to update event configuration settings.</p>
    pub fn event_data_store(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_data_store = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) or ID suffix of the ARN of the event data store for which you want to update event configuration settings.</p>
    pub fn set_event_data_store(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_data_store = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) or ID suffix of the ARN of the event data store for which you want to update event configuration settings.</p>
    pub fn get_event_data_store(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_data_store
    }
    /// <p>The maximum allowed size for events to be stored in the specified event data store. If you are using context key selectors, MaxEventSize must be set to Large.</p>
    /// This field is required.
    pub fn max_event_size(mut self, input: crate::types::MaxEventSize) -> Self {
        self.max_event_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum allowed size for events to be stored in the specified event data store. If you are using context key selectors, MaxEventSize must be set to Large.</p>
    pub fn set_max_event_size(mut self, input: ::std::option::Option<crate::types::MaxEventSize>) -> Self {
        self.max_event_size = input;
        self
    }
    /// <p>The maximum allowed size for events to be stored in the specified event data store. If you are using context key selectors, MaxEventSize must be set to Large.</p>
    pub fn get_max_event_size(&self) -> &::std::option::Option<crate::types::MaxEventSize> {
        &self.max_event_size
    }
    /// Appends an item to `context_key_selectors`.
    ///
    /// To override the contents of this collection use [`set_context_key_selectors`](Self::set_context_key_selectors).
    ///
    /// <p>A list of context key selectors that will be included to provide enriched event data.</p>
    pub fn context_key_selectors(mut self, input: crate::types::ContextKeySelector) -> Self {
        let mut v = self.context_key_selectors.unwrap_or_default();
        v.push(input);
        self.context_key_selectors = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of context key selectors that will be included to provide enriched event data.</p>
    pub fn set_context_key_selectors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ContextKeySelector>>) -> Self {
        self.context_key_selectors = input;
        self
    }
    /// <p>A list of context key selectors that will be included to provide enriched event data.</p>
    pub fn get_context_key_selectors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ContextKeySelector>> {
        &self.context_key_selectors
    }
    /// Consumes the builder and constructs a [`PutEventConfigurationInput`](crate::operation::put_event_configuration::PutEventConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::put_event_configuration::PutEventConfigurationInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::put_event_configuration::PutEventConfigurationInput {
            event_data_store: self.event_data_store,
            max_event_size: self.max_event_size,
            context_key_selectors: self.context_key_selectors,
        })
    }
}
