// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A message input, or returned from, a call to <a href="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html">Converse</a> or <a href="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_ConverseStream.html">ConverseStream</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Message {
    /// <p>The role that the message plays in the message.</p>
    pub role: crate::types::ConversationRole,
    /// <p>The message content. Note the following restrictions:</p>
    /// <ul>
    /// <li>
    /// <p>You can include up to 20 images. Each image's size, height, and width must be no more than 3.75 MB, 8000 px, and 8000 px, respectively.</p></li>
    /// <li>
    /// <p>You can include up to five documents. Each document's size must be no more than 4.5 MB.</p></li>
    /// <li>
    /// <p>If you include a <code>ContentBlock</code> with a <code>document</code> field in the array, you must also include a <code>ContentBlock</code> with a <code>text</code> field.</p></li>
    /// <li>
    /// <p>You can only include images and documents if the <code>role</code> is <code>user</code>.</p></li>
    /// </ul>
    pub content: ::std::vec::Vec<crate::types::ContentBlock>,
}
impl Message {
    /// <p>The role that the message plays in the message.</p>
    pub fn role(&self) -> &crate::types::ConversationRole {
        &self.role
    }
    /// <p>The message content. Note the following restrictions:</p>
    /// <ul>
    /// <li>
    /// <p>You can include up to 20 images. Each image's size, height, and width must be no more than 3.75 MB, 8000 px, and 8000 px, respectively.</p></li>
    /// <li>
    /// <p>You can include up to five documents. Each document's size must be no more than 4.5 MB.</p></li>
    /// <li>
    /// <p>If you include a <code>ContentBlock</code> with a <code>document</code> field in the array, you must also include a <code>ContentBlock</code> with a <code>text</code> field.</p></li>
    /// <li>
    /// <p>You can only include images and documents if the <code>role</code> is <code>user</code>.</p></li>
    /// </ul>
    pub fn content(&self) -> &[crate::types::ContentBlock] {
        use std::ops::Deref;
        self.content.deref()
    }
}
impl Message {
    /// Creates a new builder-style object to manufacture [`Message`](crate::types::Message).
    pub fn builder() -> crate::types::builders::MessageBuilder {
        crate::types::builders::MessageBuilder::default()
    }
}

/// A builder for [`Message`](crate::types::Message).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MessageBuilder {
    pub(crate) role: ::std::option::Option<crate::types::ConversationRole>,
    pub(crate) content: ::std::option::Option<::std::vec::Vec<crate::types::ContentBlock>>,
}
impl MessageBuilder {
    /// <p>The role that the message plays in the message.</p>
    /// This field is required.
    pub fn role(mut self, input: crate::types::ConversationRole) -> Self {
        self.role = ::std::option::Option::Some(input);
        self
    }
    /// <p>The role that the message plays in the message.</p>
    pub fn set_role(mut self, input: ::std::option::Option<crate::types::ConversationRole>) -> Self {
        self.role = input;
        self
    }
    /// <p>The role that the message plays in the message.</p>
    pub fn get_role(&self) -> &::std::option::Option<crate::types::ConversationRole> {
        &self.role
    }
    /// Appends an item to `content`.
    ///
    /// To override the contents of this collection use [`set_content`](Self::set_content).
    ///
    /// <p>The message content. Note the following restrictions:</p>
    /// <ul>
    /// <li>
    /// <p>You can include up to 20 images. Each image's size, height, and width must be no more than 3.75 MB, 8000 px, and 8000 px, respectively.</p></li>
    /// <li>
    /// <p>You can include up to five documents. Each document's size must be no more than 4.5 MB.</p></li>
    /// <li>
    /// <p>If you include a <code>ContentBlock</code> with a <code>document</code> field in the array, you must also include a <code>ContentBlock</code> with a <code>text</code> field.</p></li>
    /// <li>
    /// <p>You can only include images and documents if the <code>role</code> is <code>user</code>.</p></li>
    /// </ul>
    pub fn content(mut self, input: crate::types::ContentBlock) -> Self {
        let mut v = self.content.unwrap_or_default();
        v.push(input);
        self.content = ::std::option::Option::Some(v);
        self
    }
    /// <p>The message content. Note the following restrictions:</p>
    /// <ul>
    /// <li>
    /// <p>You can include up to 20 images. Each image's size, height, and width must be no more than 3.75 MB, 8000 px, and 8000 px, respectively.</p></li>
    /// <li>
    /// <p>You can include up to five documents. Each document's size must be no more than 4.5 MB.</p></li>
    /// <li>
    /// <p>If you include a <code>ContentBlock</code> with a <code>document</code> field in the array, you must also include a <code>ContentBlock</code> with a <code>text</code> field.</p></li>
    /// <li>
    /// <p>You can only include images and documents if the <code>role</code> is <code>user</code>.</p></li>
    /// </ul>
    pub fn set_content(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ContentBlock>>) -> Self {
        self.content = input;
        self
    }
    /// <p>The message content. Note the following restrictions:</p>
    /// <ul>
    /// <li>
    /// <p>You can include up to 20 images. Each image's size, height, and width must be no more than 3.75 MB, 8000 px, and 8000 px, respectively.</p></li>
    /// <li>
    /// <p>You can include up to five documents. Each document's size must be no more than 4.5 MB.</p></li>
    /// <li>
    /// <p>If you include a <code>ContentBlock</code> with a <code>document</code> field in the array, you must also include a <code>ContentBlock</code> with a <code>text</code> field.</p></li>
    /// <li>
    /// <p>You can only include images and documents if the <code>role</code> is <code>user</code>.</p></li>
    /// </ul>
    pub fn get_content(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ContentBlock>> {
        &self.content
    }
    /// Consumes the builder and constructs a [`Message`](crate::types::Message).
    /// This method will fail if any of the following fields are not set:
    /// - [`role`](crate::types::builders::MessageBuilder::role)
    /// - [`content`](crate::types::builders::MessageBuilder::content)
    pub fn build(self) -> ::std::result::Result<crate::types::Message, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Message {
            role: self.role.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "role",
                    "role was not specified but it is required when building Message",
                )
            })?,
            content: self.content.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "content",
                    "content was not specified but it is required when building Message",
                )
            })?,
        })
    }
}
