// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about each word or line of text in the input document.</p>
/// <p>For additional information, see <a href="https://docs.aws.amazon.com/textract/latest/dg/API_Block.html">Block</a> in the Amazon Textract API reference.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Block {
    /// <p>Unique identifier for the block.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The block represents a line of text or one word of text.</p>
    /// <ul>
    /// <li>
    /// <p>WORD - A word that's detected on a document page. A word is one or more ISO basic Latin script characters that aren't separated by spaces.</p></li>
    /// <li>
    /// <p>LINE - A string of tab-delimited, contiguous words that are detected on a document page</p></li>
    /// </ul>
    pub block_type: ::std::option::Option<crate::types::BlockType>,
    /// <p>The word or line of text extracted from the block.</p>
    pub text: ::std::option::Option<::std::string::String>,
    /// <p>Page number where the block appears.</p>
    pub page: ::std::option::Option<i32>,
    /// <p>Co-ordinates of the rectangle or polygon that contains the text.</p>
    pub geometry: ::std::option::Option<crate::types::Geometry>,
    /// <p>A list of child blocks of the current block. For example, a LINE object has child blocks for each WORD block that's part of the line of text.</p>
    pub relationships: ::std::option::Option<::std::vec::Vec<crate::types::RelationshipsListItem>>,
}
impl Block {
    /// <p>Unique identifier for the block.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The block represents a line of text or one word of text.</p>
    /// <ul>
    /// <li>
    /// <p>WORD - A word that's detected on a document page. A word is one or more ISO basic Latin script characters that aren't separated by spaces.</p></li>
    /// <li>
    /// <p>LINE - A string of tab-delimited, contiguous words that are detected on a document page</p></li>
    /// </ul>
    pub fn block_type(&self) -> ::std::option::Option<&crate::types::BlockType> {
        self.block_type.as_ref()
    }
    /// <p>The word or line of text extracted from the block.</p>
    pub fn text(&self) -> ::std::option::Option<&str> {
        self.text.as_deref()
    }
    /// <p>Page number where the block appears.</p>
    pub fn page(&self) -> ::std::option::Option<i32> {
        self.page
    }
    /// <p>Co-ordinates of the rectangle or polygon that contains the text.</p>
    pub fn geometry(&self) -> ::std::option::Option<&crate::types::Geometry> {
        self.geometry.as_ref()
    }
    /// <p>A list of child blocks of the current block. For example, a LINE object has child blocks for each WORD block that's part of the line of text.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.relationships.is_none()`.
    pub fn relationships(&self) -> &[crate::types::RelationshipsListItem] {
        self.relationships.as_deref().unwrap_or_default()
    }
}
impl Block {
    /// Creates a new builder-style object to manufacture [`Block`](crate::types::Block).
    pub fn builder() -> crate::types::builders::BlockBuilder {
        crate::types::builders::BlockBuilder::default()
    }
}

/// A builder for [`Block`](crate::types::Block).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BlockBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) block_type: ::std::option::Option<crate::types::BlockType>,
    pub(crate) text: ::std::option::Option<::std::string::String>,
    pub(crate) page: ::std::option::Option<i32>,
    pub(crate) geometry: ::std::option::Option<crate::types::Geometry>,
    pub(crate) relationships: ::std::option::Option<::std::vec::Vec<crate::types::RelationshipsListItem>>,
}
impl BlockBuilder {
    /// <p>Unique identifier for the block.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique identifier for the block.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>Unique identifier for the block.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The block represents a line of text or one word of text.</p>
    /// <ul>
    /// <li>
    /// <p>WORD - A word that's detected on a document page. A word is one or more ISO basic Latin script characters that aren't separated by spaces.</p></li>
    /// <li>
    /// <p>LINE - A string of tab-delimited, contiguous words that are detected on a document page</p></li>
    /// </ul>
    pub fn block_type(mut self, input: crate::types::BlockType) -> Self {
        self.block_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The block represents a line of text or one word of text.</p>
    /// <ul>
    /// <li>
    /// <p>WORD - A word that's detected on a document page. A word is one or more ISO basic Latin script characters that aren't separated by spaces.</p></li>
    /// <li>
    /// <p>LINE - A string of tab-delimited, contiguous words that are detected on a document page</p></li>
    /// </ul>
    pub fn set_block_type(mut self, input: ::std::option::Option<crate::types::BlockType>) -> Self {
        self.block_type = input;
        self
    }
    /// <p>The block represents a line of text or one word of text.</p>
    /// <ul>
    /// <li>
    /// <p>WORD - A word that's detected on a document page. A word is one or more ISO basic Latin script characters that aren't separated by spaces.</p></li>
    /// <li>
    /// <p>LINE - A string of tab-delimited, contiguous words that are detected on a document page</p></li>
    /// </ul>
    pub fn get_block_type(&self) -> &::std::option::Option<crate::types::BlockType> {
        &self.block_type
    }
    /// <p>The word or line of text extracted from the block.</p>
    pub fn text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The word or line of text extracted from the block.</p>
    pub fn set_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.text = input;
        self
    }
    /// <p>The word or line of text extracted from the block.</p>
    pub fn get_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.text
    }
    /// <p>Page number where the block appears.</p>
    pub fn page(mut self, input: i32) -> Self {
        self.page = ::std::option::Option::Some(input);
        self
    }
    /// <p>Page number where the block appears.</p>
    pub fn set_page(mut self, input: ::std::option::Option<i32>) -> Self {
        self.page = input;
        self
    }
    /// <p>Page number where the block appears.</p>
    pub fn get_page(&self) -> &::std::option::Option<i32> {
        &self.page
    }
    /// <p>Co-ordinates of the rectangle or polygon that contains the text.</p>
    pub fn geometry(mut self, input: crate::types::Geometry) -> Self {
        self.geometry = ::std::option::Option::Some(input);
        self
    }
    /// <p>Co-ordinates of the rectangle or polygon that contains the text.</p>
    pub fn set_geometry(mut self, input: ::std::option::Option<crate::types::Geometry>) -> Self {
        self.geometry = input;
        self
    }
    /// <p>Co-ordinates of the rectangle or polygon that contains the text.</p>
    pub fn get_geometry(&self) -> &::std::option::Option<crate::types::Geometry> {
        &self.geometry
    }
    /// Appends an item to `relationships`.
    ///
    /// To override the contents of this collection use [`set_relationships`](Self::set_relationships).
    ///
    /// <p>A list of child blocks of the current block. For example, a LINE object has child blocks for each WORD block that's part of the line of text.</p>
    pub fn relationships(mut self, input: crate::types::RelationshipsListItem) -> Self {
        let mut v = self.relationships.unwrap_or_default();
        v.push(input);
        self.relationships = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of child blocks of the current block. For example, a LINE object has child blocks for each WORD block that's part of the line of text.</p>
    pub fn set_relationships(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RelationshipsListItem>>) -> Self {
        self.relationships = input;
        self
    }
    /// <p>A list of child blocks of the current block. For example, a LINE object has child blocks for each WORD block that's part of the line of text.</p>
    pub fn get_relationships(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RelationshipsListItem>> {
        &self.relationships
    }
    /// Consumes the builder and constructs a [`Block`](crate::types::Block).
    pub fn build(self) -> crate::types::Block {
        crate::types::Block {
            id: self.id,
            block_type: self.block_type,
            text: self.text,
            page: self.page,
            geometry: self.geometry,
            relationships: self.relationships,
        }
    }
}
