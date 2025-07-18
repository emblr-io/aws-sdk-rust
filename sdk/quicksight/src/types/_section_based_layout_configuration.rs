// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration for a section-based layout.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SectionBasedLayoutConfiguration {
    /// <p>A list of header section configurations.</p>
    pub header_sections: ::std::vec::Vec<crate::types::HeaderFooterSectionConfiguration>,
    /// <p>A list of body section configurations.</p>
    pub body_sections: ::std::vec::Vec<crate::types::BodySectionConfiguration>,
    /// <p>A list of footer section configurations.</p>
    pub footer_sections: ::std::vec::Vec<crate::types::HeaderFooterSectionConfiguration>,
    /// <p>The options for the canvas of a section-based layout.</p>
    pub canvas_size_options: ::std::option::Option<crate::types::SectionBasedLayoutCanvasSizeOptions>,
}
impl SectionBasedLayoutConfiguration {
    /// <p>A list of header section configurations.</p>
    pub fn header_sections(&self) -> &[crate::types::HeaderFooterSectionConfiguration] {
        use std::ops::Deref;
        self.header_sections.deref()
    }
    /// <p>A list of body section configurations.</p>
    pub fn body_sections(&self) -> &[crate::types::BodySectionConfiguration] {
        use std::ops::Deref;
        self.body_sections.deref()
    }
    /// <p>A list of footer section configurations.</p>
    pub fn footer_sections(&self) -> &[crate::types::HeaderFooterSectionConfiguration] {
        use std::ops::Deref;
        self.footer_sections.deref()
    }
    /// <p>The options for the canvas of a section-based layout.</p>
    pub fn canvas_size_options(&self) -> ::std::option::Option<&crate::types::SectionBasedLayoutCanvasSizeOptions> {
        self.canvas_size_options.as_ref()
    }
}
impl SectionBasedLayoutConfiguration {
    /// Creates a new builder-style object to manufacture [`SectionBasedLayoutConfiguration`](crate::types::SectionBasedLayoutConfiguration).
    pub fn builder() -> crate::types::builders::SectionBasedLayoutConfigurationBuilder {
        crate::types::builders::SectionBasedLayoutConfigurationBuilder::default()
    }
}

/// A builder for [`SectionBasedLayoutConfiguration`](crate::types::SectionBasedLayoutConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SectionBasedLayoutConfigurationBuilder {
    pub(crate) header_sections: ::std::option::Option<::std::vec::Vec<crate::types::HeaderFooterSectionConfiguration>>,
    pub(crate) body_sections: ::std::option::Option<::std::vec::Vec<crate::types::BodySectionConfiguration>>,
    pub(crate) footer_sections: ::std::option::Option<::std::vec::Vec<crate::types::HeaderFooterSectionConfiguration>>,
    pub(crate) canvas_size_options: ::std::option::Option<crate::types::SectionBasedLayoutCanvasSizeOptions>,
}
impl SectionBasedLayoutConfigurationBuilder {
    /// Appends an item to `header_sections`.
    ///
    /// To override the contents of this collection use [`set_header_sections`](Self::set_header_sections).
    ///
    /// <p>A list of header section configurations.</p>
    pub fn header_sections(mut self, input: crate::types::HeaderFooterSectionConfiguration) -> Self {
        let mut v = self.header_sections.unwrap_or_default();
        v.push(input);
        self.header_sections = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of header section configurations.</p>
    pub fn set_header_sections(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::HeaderFooterSectionConfiguration>>) -> Self {
        self.header_sections = input;
        self
    }
    /// <p>A list of header section configurations.</p>
    pub fn get_header_sections(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::HeaderFooterSectionConfiguration>> {
        &self.header_sections
    }
    /// Appends an item to `body_sections`.
    ///
    /// To override the contents of this collection use [`set_body_sections`](Self::set_body_sections).
    ///
    /// <p>A list of body section configurations.</p>
    pub fn body_sections(mut self, input: crate::types::BodySectionConfiguration) -> Self {
        let mut v = self.body_sections.unwrap_or_default();
        v.push(input);
        self.body_sections = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of body section configurations.</p>
    pub fn set_body_sections(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::BodySectionConfiguration>>) -> Self {
        self.body_sections = input;
        self
    }
    /// <p>A list of body section configurations.</p>
    pub fn get_body_sections(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BodySectionConfiguration>> {
        &self.body_sections
    }
    /// Appends an item to `footer_sections`.
    ///
    /// To override the contents of this collection use [`set_footer_sections`](Self::set_footer_sections).
    ///
    /// <p>A list of footer section configurations.</p>
    pub fn footer_sections(mut self, input: crate::types::HeaderFooterSectionConfiguration) -> Self {
        let mut v = self.footer_sections.unwrap_or_default();
        v.push(input);
        self.footer_sections = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of footer section configurations.</p>
    pub fn set_footer_sections(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::HeaderFooterSectionConfiguration>>) -> Self {
        self.footer_sections = input;
        self
    }
    /// <p>A list of footer section configurations.</p>
    pub fn get_footer_sections(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::HeaderFooterSectionConfiguration>> {
        &self.footer_sections
    }
    /// <p>The options for the canvas of a section-based layout.</p>
    /// This field is required.
    pub fn canvas_size_options(mut self, input: crate::types::SectionBasedLayoutCanvasSizeOptions) -> Self {
        self.canvas_size_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The options for the canvas of a section-based layout.</p>
    pub fn set_canvas_size_options(mut self, input: ::std::option::Option<crate::types::SectionBasedLayoutCanvasSizeOptions>) -> Self {
        self.canvas_size_options = input;
        self
    }
    /// <p>The options for the canvas of a section-based layout.</p>
    pub fn get_canvas_size_options(&self) -> &::std::option::Option<crate::types::SectionBasedLayoutCanvasSizeOptions> {
        &self.canvas_size_options
    }
    /// Consumes the builder and constructs a [`SectionBasedLayoutConfiguration`](crate::types::SectionBasedLayoutConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`header_sections`](crate::types::builders::SectionBasedLayoutConfigurationBuilder::header_sections)
    /// - [`body_sections`](crate::types::builders::SectionBasedLayoutConfigurationBuilder::body_sections)
    /// - [`footer_sections`](crate::types::builders::SectionBasedLayoutConfigurationBuilder::footer_sections)
    pub fn build(self) -> ::std::result::Result<crate::types::SectionBasedLayoutConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SectionBasedLayoutConfiguration {
            header_sections: self.header_sections.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "header_sections",
                    "header_sections was not specified but it is required when building SectionBasedLayoutConfiguration",
                )
            })?,
            body_sections: self.body_sections.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "body_sections",
                    "body_sections was not specified but it is required when building SectionBasedLayoutConfiguration",
                )
            })?,
            footer_sections: self.footer_sections.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "footer_sections",
                    "footer_sections was not specified but it is required when building SectionBasedLayoutConfiguration",
                )
            })?,
            canvas_size_options: self.canvas_size_options,
        })
    }
}
