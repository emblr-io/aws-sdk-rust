// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the contexts that a user is using in a session. You can configure Amazon Lex V2 to set a context when an intent is fulfilled, or you can set a context using the , , or operations.</p>
/// <p>Use a context to indicate to Amazon Lex V2 intents that should be used as follow-up intents. For example, if the active context is <code>order-fulfilled</code>, only intents that have <code>order-fulfilled</code> configured as a trigger are considered for follow up.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ActiveContext {
    /// <p>The name of the context.</p>
    pub name: ::std::string::String,
    /// <p>Indicates the number of turns or seconds that the context is active. Once the time to live expires, the context is no longer returned in a response.</p>
    pub time_to_live: ::std::option::Option<crate::types::ActiveContextTimeToLive>,
    /// <p>A list of contexts active for the request. A context can be activated when a previous intent is fulfilled, or by including the context in the request.</p>
    /// <p>If you don't specify a list of contexts, Amazon Lex V2 will use the current list of contexts for the session. If you specify an empty list, all contexts for the session are cleared.</p>
    pub context_attributes: ::std::collections::HashMap<::std::string::String, ::std::string::String>,
}
impl ActiveContext {
    /// <p>The name of the context.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>Indicates the number of turns or seconds that the context is active. Once the time to live expires, the context is no longer returned in a response.</p>
    pub fn time_to_live(&self) -> ::std::option::Option<&crate::types::ActiveContextTimeToLive> {
        self.time_to_live.as_ref()
    }
    /// <p>A list of contexts active for the request. A context can be activated when a previous intent is fulfilled, or by including the context in the request.</p>
    /// <p>If you don't specify a list of contexts, Amazon Lex V2 will use the current list of contexts for the session. If you specify an empty list, all contexts for the session are cleared.</p>
    pub fn context_attributes(&self) -> &::std::collections::HashMap<::std::string::String, ::std::string::String> {
        &self.context_attributes
    }
}
impl ActiveContext {
    /// Creates a new builder-style object to manufacture [`ActiveContext`](crate::types::ActiveContext).
    pub fn builder() -> crate::types::builders::ActiveContextBuilder {
        crate::types::builders::ActiveContextBuilder::default()
    }
}

/// A builder for [`ActiveContext`](crate::types::ActiveContext).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ActiveContextBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) time_to_live: ::std::option::Option<crate::types::ActiveContextTimeToLive>,
    pub(crate) context_attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl ActiveContextBuilder {
    /// <p>The name of the context.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the context.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the context.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Indicates the number of turns or seconds that the context is active. Once the time to live expires, the context is no longer returned in a response.</p>
    /// This field is required.
    pub fn time_to_live(mut self, input: crate::types::ActiveContextTimeToLive) -> Self {
        self.time_to_live = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the number of turns or seconds that the context is active. Once the time to live expires, the context is no longer returned in a response.</p>
    pub fn set_time_to_live(mut self, input: ::std::option::Option<crate::types::ActiveContextTimeToLive>) -> Self {
        self.time_to_live = input;
        self
    }
    /// <p>Indicates the number of turns or seconds that the context is active. Once the time to live expires, the context is no longer returned in a response.</p>
    pub fn get_time_to_live(&self) -> &::std::option::Option<crate::types::ActiveContextTimeToLive> {
        &self.time_to_live
    }
    /// Adds a key-value pair to `context_attributes`.
    ///
    /// To override the contents of this collection use [`set_context_attributes`](Self::set_context_attributes).
    ///
    /// <p>A list of contexts active for the request. A context can be activated when a previous intent is fulfilled, or by including the context in the request.</p>
    /// <p>If you don't specify a list of contexts, Amazon Lex V2 will use the current list of contexts for the session. If you specify an empty list, all contexts for the session are cleared.</p>
    pub fn context_attributes(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.context_attributes.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.context_attributes = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A list of contexts active for the request. A context can be activated when a previous intent is fulfilled, or by including the context in the request.</p>
    /// <p>If you don't specify a list of contexts, Amazon Lex V2 will use the current list of contexts for the session. If you specify an empty list, all contexts for the session are cleared.</p>
    pub fn set_context_attributes(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.context_attributes = input;
        self
    }
    /// <p>A list of contexts active for the request. A context can be activated when a previous intent is fulfilled, or by including the context in the request.</p>
    /// <p>If you don't specify a list of contexts, Amazon Lex V2 will use the current list of contexts for the session. If you specify an empty list, all contexts for the session are cleared.</p>
    pub fn get_context_attributes(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.context_attributes
    }
    /// Consumes the builder and constructs a [`ActiveContext`](crate::types::ActiveContext).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::ActiveContextBuilder::name)
    /// - [`context_attributes`](crate::types::builders::ActiveContextBuilder::context_attributes)
    pub fn build(self) -> ::std::result::Result<crate::types::ActiveContext, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ActiveContext {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building ActiveContext",
                )
            })?,
            time_to_live: self.time_to_live,
            context_attributes: self.context_attributes.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "context_attributes",
                    "context_attributes was not specified but it is required when building ActiveContext",
                )
            })?,
        })
    }
}
