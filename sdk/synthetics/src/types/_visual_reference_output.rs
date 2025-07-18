// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>If this canary performs visual monitoring by comparing screenshots, this structure contains the ID of the canary run that is used as the baseline for screenshots, and the coordinates of any parts of those screenshots that are ignored during visual monitoring comparison.</p>
/// <p>Visual monitoring is supported only on canaries running the <b>syn-puppeteer-node-3.2</b> runtime or later.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VisualReferenceOutput {
    /// <p>An array of screenshots that are used as the baseline for comparisons during visual monitoring.</p>
    pub base_screenshots: ::std::option::Option<::std::vec::Vec<crate::types::BaseScreenshot>>,
    /// <p>The ID of the canary run that produced the baseline screenshots that are used for visual monitoring comparisons by this canary.</p>
    pub base_canary_run_id: ::std::option::Option<::std::string::String>,
}
impl VisualReferenceOutput {
    /// <p>An array of screenshots that are used as the baseline for comparisons during visual monitoring.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.base_screenshots.is_none()`.
    pub fn base_screenshots(&self) -> &[crate::types::BaseScreenshot] {
        self.base_screenshots.as_deref().unwrap_or_default()
    }
    /// <p>The ID of the canary run that produced the baseline screenshots that are used for visual monitoring comparisons by this canary.</p>
    pub fn base_canary_run_id(&self) -> ::std::option::Option<&str> {
        self.base_canary_run_id.as_deref()
    }
}
impl VisualReferenceOutput {
    /// Creates a new builder-style object to manufacture [`VisualReferenceOutput`](crate::types::VisualReferenceOutput).
    pub fn builder() -> crate::types::builders::VisualReferenceOutputBuilder {
        crate::types::builders::VisualReferenceOutputBuilder::default()
    }
}

/// A builder for [`VisualReferenceOutput`](crate::types::VisualReferenceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VisualReferenceOutputBuilder {
    pub(crate) base_screenshots: ::std::option::Option<::std::vec::Vec<crate::types::BaseScreenshot>>,
    pub(crate) base_canary_run_id: ::std::option::Option<::std::string::String>,
}
impl VisualReferenceOutputBuilder {
    /// Appends an item to `base_screenshots`.
    ///
    /// To override the contents of this collection use [`set_base_screenshots`](Self::set_base_screenshots).
    ///
    /// <p>An array of screenshots that are used as the baseline for comparisons during visual monitoring.</p>
    pub fn base_screenshots(mut self, input: crate::types::BaseScreenshot) -> Self {
        let mut v = self.base_screenshots.unwrap_or_default();
        v.push(input);
        self.base_screenshots = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of screenshots that are used as the baseline for comparisons during visual monitoring.</p>
    pub fn set_base_screenshots(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::BaseScreenshot>>) -> Self {
        self.base_screenshots = input;
        self
    }
    /// <p>An array of screenshots that are used as the baseline for comparisons during visual monitoring.</p>
    pub fn get_base_screenshots(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BaseScreenshot>> {
        &self.base_screenshots
    }
    /// <p>The ID of the canary run that produced the baseline screenshots that are used for visual monitoring comparisons by this canary.</p>
    pub fn base_canary_run_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.base_canary_run_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the canary run that produced the baseline screenshots that are used for visual monitoring comparisons by this canary.</p>
    pub fn set_base_canary_run_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.base_canary_run_id = input;
        self
    }
    /// <p>The ID of the canary run that produced the baseline screenshots that are used for visual monitoring comparisons by this canary.</p>
    pub fn get_base_canary_run_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.base_canary_run_id
    }
    /// Consumes the builder and constructs a [`VisualReferenceOutput`](crate::types::VisualReferenceOutput).
    pub fn build(self) -> crate::types::VisualReferenceOutput {
        crate::types::VisualReferenceOutput {
            base_screenshots: self.base_screenshots,
            base_canary_run_id: self.base_canary_run_id,
        }
    }
}
