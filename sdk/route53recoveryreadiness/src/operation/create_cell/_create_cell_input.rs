// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateCellInput {
    /// <p>The name of the cell to create.</p>
    pub cell_name: ::std::option::Option<::std::string::String>,
    /// <p>A list of cell Amazon Resource Names (ARNs) contained within this cell, for use in nested cells. For example, Availability Zones within specific Amazon Web Services Regions.</p>
    pub cells: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A collection of tags associated with a resource.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateCellInput {
    /// <p>The name of the cell to create.</p>
    pub fn cell_name(&self) -> ::std::option::Option<&str> {
        self.cell_name.as_deref()
    }
    /// <p>A list of cell Amazon Resource Names (ARNs) contained within this cell, for use in nested cells. For example, Availability Zones within specific Amazon Web Services Regions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.cells.is_none()`.
    pub fn cells(&self) -> &[::std::string::String] {
        self.cells.as_deref().unwrap_or_default()
    }
    /// <p>A collection of tags associated with a resource.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl CreateCellInput {
    /// Creates a new builder-style object to manufacture [`CreateCellInput`](crate::operation::create_cell::CreateCellInput).
    pub fn builder() -> crate::operation::create_cell::builders::CreateCellInputBuilder {
        crate::operation::create_cell::builders::CreateCellInputBuilder::default()
    }
}

/// A builder for [`CreateCellInput`](crate::operation::create_cell::CreateCellInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateCellInputBuilder {
    pub(crate) cell_name: ::std::option::Option<::std::string::String>,
    pub(crate) cells: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateCellInputBuilder {
    /// <p>The name of the cell to create.</p>
    /// This field is required.
    pub fn cell_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cell_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the cell to create.</p>
    pub fn set_cell_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cell_name = input;
        self
    }
    /// <p>The name of the cell to create.</p>
    pub fn get_cell_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.cell_name
    }
    /// Appends an item to `cells`.
    ///
    /// To override the contents of this collection use [`set_cells`](Self::set_cells).
    ///
    /// <p>A list of cell Amazon Resource Names (ARNs) contained within this cell, for use in nested cells. For example, Availability Zones within specific Amazon Web Services Regions.</p>
    pub fn cells(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.cells.unwrap_or_default();
        v.push(input.into());
        self.cells = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of cell Amazon Resource Names (ARNs) contained within this cell, for use in nested cells. For example, Availability Zones within specific Amazon Web Services Regions.</p>
    pub fn set_cells(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.cells = input;
        self
    }
    /// <p>A list of cell Amazon Resource Names (ARNs) contained within this cell, for use in nested cells. For example, Availability Zones within specific Amazon Web Services Regions.</p>
    pub fn get_cells(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.cells
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A collection of tags associated with a resource.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A collection of tags associated with a resource.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A collection of tags associated with a resource.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateCellInput`](crate::operation::create_cell::CreateCellInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_cell::CreateCellInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_cell::CreateCellInput {
            cell_name: self.cell_name,
            cells: self.cells,
            tags: self.tags,
        })
    }
}
