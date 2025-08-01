// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Specify the details for each additional DASH manifest that you want the service to generate for this output group. Each manifest can reference a different subset of outputs in the group.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DashAdditionalManifest {
    /// Specify a name modifier that the service adds to the name of this manifest to make it different from the file names of the other main manifests in the output group. For example, say that the default main manifest for your DASH group is film-name.mpd. If you enter "-no-premium" for this setting, then the file name the service generates for this top-level manifest is film-name-no-premium.mpd.
    pub manifest_name_modifier: ::std::option::Option<::std::string::String>,
    /// Specify the outputs that you want this additional top-level manifest to reference.
    pub selected_outputs: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DashAdditionalManifest {
    /// Specify a name modifier that the service adds to the name of this manifest to make it different from the file names of the other main manifests in the output group. For example, say that the default main manifest for your DASH group is film-name.mpd. If you enter "-no-premium" for this setting, then the file name the service generates for this top-level manifest is film-name-no-premium.mpd.
    pub fn manifest_name_modifier(&self) -> ::std::option::Option<&str> {
        self.manifest_name_modifier.as_deref()
    }
    /// Specify the outputs that you want this additional top-level manifest to reference.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.selected_outputs.is_none()`.
    pub fn selected_outputs(&self) -> &[::std::string::String] {
        self.selected_outputs.as_deref().unwrap_or_default()
    }
}
impl DashAdditionalManifest {
    /// Creates a new builder-style object to manufacture [`DashAdditionalManifest`](crate::types::DashAdditionalManifest).
    pub fn builder() -> crate::types::builders::DashAdditionalManifestBuilder {
        crate::types::builders::DashAdditionalManifestBuilder::default()
    }
}

/// A builder for [`DashAdditionalManifest`](crate::types::DashAdditionalManifest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DashAdditionalManifestBuilder {
    pub(crate) manifest_name_modifier: ::std::option::Option<::std::string::String>,
    pub(crate) selected_outputs: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DashAdditionalManifestBuilder {
    /// Specify a name modifier that the service adds to the name of this manifest to make it different from the file names of the other main manifests in the output group. For example, say that the default main manifest for your DASH group is film-name.mpd. If you enter "-no-premium" for this setting, then the file name the service generates for this top-level manifest is film-name-no-premium.mpd.
    pub fn manifest_name_modifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.manifest_name_modifier = ::std::option::Option::Some(input.into());
        self
    }
    /// Specify a name modifier that the service adds to the name of this manifest to make it different from the file names of the other main manifests in the output group. For example, say that the default main manifest for your DASH group is film-name.mpd. If you enter "-no-premium" for this setting, then the file name the service generates for this top-level manifest is film-name-no-premium.mpd.
    pub fn set_manifest_name_modifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.manifest_name_modifier = input;
        self
    }
    /// Specify a name modifier that the service adds to the name of this manifest to make it different from the file names of the other main manifests in the output group. For example, say that the default main manifest for your DASH group is film-name.mpd. If you enter "-no-premium" for this setting, then the file name the service generates for this top-level manifest is film-name-no-premium.mpd.
    pub fn get_manifest_name_modifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.manifest_name_modifier
    }
    /// Appends an item to `selected_outputs`.
    ///
    /// To override the contents of this collection use [`set_selected_outputs`](Self::set_selected_outputs).
    ///
    /// Specify the outputs that you want this additional top-level manifest to reference.
    pub fn selected_outputs(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.selected_outputs.unwrap_or_default();
        v.push(input.into());
        self.selected_outputs = ::std::option::Option::Some(v);
        self
    }
    /// Specify the outputs that you want this additional top-level manifest to reference.
    pub fn set_selected_outputs(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.selected_outputs = input;
        self
    }
    /// Specify the outputs that you want this additional top-level manifest to reference.
    pub fn get_selected_outputs(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.selected_outputs
    }
    /// Consumes the builder and constructs a [`DashAdditionalManifest`](crate::types::DashAdditionalManifest).
    pub fn build(self) -> crate::types::DashAdditionalManifest {
        crate::types::DashAdditionalManifest {
            manifest_name_modifier: self.manifest_name_modifier,
            selected_outputs: self.selected_outputs,
        }
    }
}
