// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the next action that the bot should take in its interaction with the user and provides information about the context in which the action takes place. Use the <code>DialogAction</code> data type to set the interaction to a specific state, or to return the interaction to a previous state.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct DialogAction {
    /// <p>The next action that the bot should take in its interaction with the user. The possible values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>ConfirmIntent</code> - The next action is asking the user if the intent is complete and ready to be fulfilled. This is a yes/no question such as "Place the order?"</p></li>
    /// <li>
    /// <p><code>Close</code> - Indicates that the there will not be a response from the user. For example, the statement "Your order has been placed" does not require a response.</p></li>
    /// <li>
    /// <p><code>Delegate</code> - The next action is determined by Amazon Lex.</p></li>
    /// <li>
    /// <p><code>ElicitIntent</code> - The next action is to determine the intent that the user wants to fulfill.</p></li>
    /// <li>
    /// <p><code>ElicitSlot</code> - The next action is to elicit a slot value from the user.</p></li>
    /// </ul>
    pub r#type: crate::types::DialogActionType,
    /// <p>The name of the intent.</p>
    pub intent_name: ::std::option::Option<::std::string::String>,
    /// <p>Map of the slots that have been gathered and their values.</p>
    pub slots: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The name of the slot that should be elicited from the user.</p>
    pub slot_to_elicit: ::std::option::Option<::std::string::String>,
    /// <p>The fulfillment state of the intent. The possible values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>Failed</code> - The Lambda function associated with the intent failed to fulfill the intent.</p></li>
    /// <li>
    /// <p><code>Fulfilled</code> - The intent has fulfilled by the Lambda function associated with the intent.</p></li>
    /// <li>
    /// <p><code>ReadyForFulfillment</code> - All of the information necessary for the intent is present and the intent ready to be fulfilled by the client application.</p></li>
    /// </ul>
    pub fulfillment_state: ::std::option::Option<crate::types::FulfillmentState>,
    /// <p>The message that should be shown to the user. If you don't specify a message, Amazon Lex will use the message configured for the intent.</p>
    pub message: ::std::option::Option<::std::string::String>,
    /// <ul>
    /// <li>
    /// <p><code>PlainText</code> - The message contains plain UTF-8 text.</p></li>
    /// <li>
    /// <p><code>CustomPayload</code> - The message is a custom format for the client.</p></li>
    /// <li>
    /// <p><code>SSML</code> - The message contains text formatted for voice output.</p></li>
    /// <li>
    /// <p><code>Composite</code> - The message contains an escaped JSON object containing one or more messages. For more information, see <a href="https://docs.aws.amazon.com/lex/latest/dg/howitworks-manage-prompts.html">Message Groups</a>.</p></li>
    /// </ul>
    pub message_format: ::std::option::Option<crate::types::MessageFormatType>,
}
impl DialogAction {
    /// <p>The next action that the bot should take in its interaction with the user. The possible values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>ConfirmIntent</code> - The next action is asking the user if the intent is complete and ready to be fulfilled. This is a yes/no question such as "Place the order?"</p></li>
    /// <li>
    /// <p><code>Close</code> - Indicates that the there will not be a response from the user. For example, the statement "Your order has been placed" does not require a response.</p></li>
    /// <li>
    /// <p><code>Delegate</code> - The next action is determined by Amazon Lex.</p></li>
    /// <li>
    /// <p><code>ElicitIntent</code> - The next action is to determine the intent that the user wants to fulfill.</p></li>
    /// <li>
    /// <p><code>ElicitSlot</code> - The next action is to elicit a slot value from the user.</p></li>
    /// </ul>
    pub fn r#type(&self) -> &crate::types::DialogActionType {
        &self.r#type
    }
    /// <p>The name of the intent.</p>
    pub fn intent_name(&self) -> ::std::option::Option<&str> {
        self.intent_name.as_deref()
    }
    /// <p>Map of the slots that have been gathered and their values.</p>
    pub fn slots(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.slots.as_ref()
    }
    /// <p>The name of the slot that should be elicited from the user.</p>
    pub fn slot_to_elicit(&self) -> ::std::option::Option<&str> {
        self.slot_to_elicit.as_deref()
    }
    /// <p>The fulfillment state of the intent. The possible values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>Failed</code> - The Lambda function associated with the intent failed to fulfill the intent.</p></li>
    /// <li>
    /// <p><code>Fulfilled</code> - The intent has fulfilled by the Lambda function associated with the intent.</p></li>
    /// <li>
    /// <p><code>ReadyForFulfillment</code> - All of the information necessary for the intent is present and the intent ready to be fulfilled by the client application.</p></li>
    /// </ul>
    pub fn fulfillment_state(&self) -> ::std::option::Option<&crate::types::FulfillmentState> {
        self.fulfillment_state.as_ref()
    }
    /// <p>The message that should be shown to the user. If you don't specify a message, Amazon Lex will use the message configured for the intent.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
    /// <ul>
    /// <li>
    /// <p><code>PlainText</code> - The message contains plain UTF-8 text.</p></li>
    /// <li>
    /// <p><code>CustomPayload</code> - The message is a custom format for the client.</p></li>
    /// <li>
    /// <p><code>SSML</code> - The message contains text formatted for voice output.</p></li>
    /// <li>
    /// <p><code>Composite</code> - The message contains an escaped JSON object containing one or more messages. For more information, see <a href="https://docs.aws.amazon.com/lex/latest/dg/howitworks-manage-prompts.html">Message Groups</a>.</p></li>
    /// </ul>
    pub fn message_format(&self) -> ::std::option::Option<&crate::types::MessageFormatType> {
        self.message_format.as_ref()
    }
}
impl ::std::fmt::Debug for DialogAction {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DialogAction");
        formatter.field("r#type", &self.r#type);
        formatter.field("intent_name", &self.intent_name);
        formatter.field("slots", &"*** Sensitive Data Redacted ***");
        formatter.field("slot_to_elicit", &self.slot_to_elicit);
        formatter.field("fulfillment_state", &self.fulfillment_state);
        formatter.field("message", &"*** Sensitive Data Redacted ***");
        formatter.field("message_format", &self.message_format);
        formatter.finish()
    }
}
impl DialogAction {
    /// Creates a new builder-style object to manufacture [`DialogAction`](crate::types::DialogAction).
    pub fn builder() -> crate::types::builders::DialogActionBuilder {
        crate::types::builders::DialogActionBuilder::default()
    }
}

/// A builder for [`DialogAction`](crate::types::DialogAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct DialogActionBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::DialogActionType>,
    pub(crate) intent_name: ::std::option::Option<::std::string::String>,
    pub(crate) slots: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) slot_to_elicit: ::std::option::Option<::std::string::String>,
    pub(crate) fulfillment_state: ::std::option::Option<crate::types::FulfillmentState>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) message_format: ::std::option::Option<crate::types::MessageFormatType>,
}
impl DialogActionBuilder {
    /// <p>The next action that the bot should take in its interaction with the user. The possible values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>ConfirmIntent</code> - The next action is asking the user if the intent is complete and ready to be fulfilled. This is a yes/no question such as "Place the order?"</p></li>
    /// <li>
    /// <p><code>Close</code> - Indicates that the there will not be a response from the user. For example, the statement "Your order has been placed" does not require a response.</p></li>
    /// <li>
    /// <p><code>Delegate</code> - The next action is determined by Amazon Lex.</p></li>
    /// <li>
    /// <p><code>ElicitIntent</code> - The next action is to determine the intent that the user wants to fulfill.</p></li>
    /// <li>
    /// <p><code>ElicitSlot</code> - The next action is to elicit a slot value from the user.</p></li>
    /// </ul>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::DialogActionType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The next action that the bot should take in its interaction with the user. The possible values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>ConfirmIntent</code> - The next action is asking the user if the intent is complete and ready to be fulfilled. This is a yes/no question such as "Place the order?"</p></li>
    /// <li>
    /// <p><code>Close</code> - Indicates that the there will not be a response from the user. For example, the statement "Your order has been placed" does not require a response.</p></li>
    /// <li>
    /// <p><code>Delegate</code> - The next action is determined by Amazon Lex.</p></li>
    /// <li>
    /// <p><code>ElicitIntent</code> - The next action is to determine the intent that the user wants to fulfill.</p></li>
    /// <li>
    /// <p><code>ElicitSlot</code> - The next action is to elicit a slot value from the user.</p></li>
    /// </ul>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::DialogActionType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The next action that the bot should take in its interaction with the user. The possible values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>ConfirmIntent</code> - The next action is asking the user if the intent is complete and ready to be fulfilled. This is a yes/no question such as "Place the order?"</p></li>
    /// <li>
    /// <p><code>Close</code> - Indicates that the there will not be a response from the user. For example, the statement "Your order has been placed" does not require a response.</p></li>
    /// <li>
    /// <p><code>Delegate</code> - The next action is determined by Amazon Lex.</p></li>
    /// <li>
    /// <p><code>ElicitIntent</code> - The next action is to determine the intent that the user wants to fulfill.</p></li>
    /// <li>
    /// <p><code>ElicitSlot</code> - The next action is to elicit a slot value from the user.</p></li>
    /// </ul>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::DialogActionType> {
        &self.r#type
    }
    /// <p>The name of the intent.</p>
    pub fn intent_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.intent_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the intent.</p>
    pub fn set_intent_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.intent_name = input;
        self
    }
    /// <p>The name of the intent.</p>
    pub fn get_intent_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.intent_name
    }
    /// Adds a key-value pair to `slots`.
    ///
    /// To override the contents of this collection use [`set_slots`](Self::set_slots).
    ///
    /// <p>Map of the slots that have been gathered and their values.</p>
    pub fn slots(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.slots.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.slots = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Map of the slots that have been gathered and their values.</p>
    pub fn set_slots(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.slots = input;
        self
    }
    /// <p>Map of the slots that have been gathered and their values.</p>
    pub fn get_slots(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.slots
    }
    /// <p>The name of the slot that should be elicited from the user.</p>
    pub fn slot_to_elicit(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.slot_to_elicit = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the slot that should be elicited from the user.</p>
    pub fn set_slot_to_elicit(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.slot_to_elicit = input;
        self
    }
    /// <p>The name of the slot that should be elicited from the user.</p>
    pub fn get_slot_to_elicit(&self) -> &::std::option::Option<::std::string::String> {
        &self.slot_to_elicit
    }
    /// <p>The fulfillment state of the intent. The possible values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>Failed</code> - The Lambda function associated with the intent failed to fulfill the intent.</p></li>
    /// <li>
    /// <p><code>Fulfilled</code> - The intent has fulfilled by the Lambda function associated with the intent.</p></li>
    /// <li>
    /// <p><code>ReadyForFulfillment</code> - All of the information necessary for the intent is present and the intent ready to be fulfilled by the client application.</p></li>
    /// </ul>
    pub fn fulfillment_state(mut self, input: crate::types::FulfillmentState) -> Self {
        self.fulfillment_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The fulfillment state of the intent. The possible values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>Failed</code> - The Lambda function associated with the intent failed to fulfill the intent.</p></li>
    /// <li>
    /// <p><code>Fulfilled</code> - The intent has fulfilled by the Lambda function associated with the intent.</p></li>
    /// <li>
    /// <p><code>ReadyForFulfillment</code> - All of the information necessary for the intent is present and the intent ready to be fulfilled by the client application.</p></li>
    /// </ul>
    pub fn set_fulfillment_state(mut self, input: ::std::option::Option<crate::types::FulfillmentState>) -> Self {
        self.fulfillment_state = input;
        self
    }
    /// <p>The fulfillment state of the intent. The possible values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>Failed</code> - The Lambda function associated with the intent failed to fulfill the intent.</p></li>
    /// <li>
    /// <p><code>Fulfilled</code> - The intent has fulfilled by the Lambda function associated with the intent.</p></li>
    /// <li>
    /// <p><code>ReadyForFulfillment</code> - All of the information necessary for the intent is present and the intent ready to be fulfilled by the client application.</p></li>
    /// </ul>
    pub fn get_fulfillment_state(&self) -> &::std::option::Option<crate::types::FulfillmentState> {
        &self.fulfillment_state
    }
    /// <p>The message that should be shown to the user. If you don't specify a message, Amazon Lex will use the message configured for the intent.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The message that should be shown to the user. If you don't specify a message, Amazon Lex will use the message configured for the intent.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The message that should be shown to the user. If you don't specify a message, Amazon Lex will use the message configured for the intent.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// <ul>
    /// <li>
    /// <p><code>PlainText</code> - The message contains plain UTF-8 text.</p></li>
    /// <li>
    /// <p><code>CustomPayload</code> - The message is a custom format for the client.</p></li>
    /// <li>
    /// <p><code>SSML</code> - The message contains text formatted for voice output.</p></li>
    /// <li>
    /// <p><code>Composite</code> - The message contains an escaped JSON object containing one or more messages. For more information, see <a href="https://docs.aws.amazon.com/lex/latest/dg/howitworks-manage-prompts.html">Message Groups</a>.</p></li>
    /// </ul>
    pub fn message_format(mut self, input: crate::types::MessageFormatType) -> Self {
        self.message_format = ::std::option::Option::Some(input);
        self
    }
    /// <ul>
    /// <li>
    /// <p><code>PlainText</code> - The message contains plain UTF-8 text.</p></li>
    /// <li>
    /// <p><code>CustomPayload</code> - The message is a custom format for the client.</p></li>
    /// <li>
    /// <p><code>SSML</code> - The message contains text formatted for voice output.</p></li>
    /// <li>
    /// <p><code>Composite</code> - The message contains an escaped JSON object containing one or more messages. For more information, see <a href="https://docs.aws.amazon.com/lex/latest/dg/howitworks-manage-prompts.html">Message Groups</a>.</p></li>
    /// </ul>
    pub fn set_message_format(mut self, input: ::std::option::Option<crate::types::MessageFormatType>) -> Self {
        self.message_format = input;
        self
    }
    /// <ul>
    /// <li>
    /// <p><code>PlainText</code> - The message contains plain UTF-8 text.</p></li>
    /// <li>
    /// <p><code>CustomPayload</code> - The message is a custom format for the client.</p></li>
    /// <li>
    /// <p><code>SSML</code> - The message contains text formatted for voice output.</p></li>
    /// <li>
    /// <p><code>Composite</code> - The message contains an escaped JSON object containing one or more messages. For more information, see <a href="https://docs.aws.amazon.com/lex/latest/dg/howitworks-manage-prompts.html">Message Groups</a>.</p></li>
    /// </ul>
    pub fn get_message_format(&self) -> &::std::option::Option<crate::types::MessageFormatType> {
        &self.message_format
    }
    /// Consumes the builder and constructs a [`DialogAction`](crate::types::DialogAction).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::DialogActionBuilder::type)
    pub fn build(self) -> ::std::result::Result<crate::types::DialogAction, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DialogAction {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building DialogAction",
                )
            })?,
            intent_name: self.intent_name,
            slots: self.slots,
            slot_to_elicit: self.slot_to_elicit,
            fulfillment_state: self.fulfillment_state,
            message: self.message,
            message_format: self.message_format,
        })
    }
}
impl ::std::fmt::Debug for DialogActionBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DialogActionBuilder");
        formatter.field("r#type", &self.r#type);
        formatter.field("intent_name", &self.intent_name);
        formatter.field("slots", &"*** Sensitive Data Redacted ***");
        formatter.field("slot_to_elicit", &self.slot_to_elicit);
        formatter.field("fulfillment_state", &self.fulfillment_state);
        formatter.field("message", &"*** Sensitive Data Redacted ***");
        formatter.field("message_format", &self.message_format);
        formatter.finish()
    }
}
