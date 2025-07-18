// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details about an optimizer associated with a table.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TableOptimizer {
    /// <p>The type of table optimizer. The valid values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>compaction</code>: for managing compaction with a table optimizer.</p></li>
    /// <li>
    /// <p><code>retention</code>: for managing the retention of snapshot with a table optimizer.</p></li>
    /// <li>
    /// <p><code>orphan_file_deletion</code>: for managing the deletion of orphan files with a table optimizer.</p></li>
    /// </ul>
    pub r#type: ::std::option::Option<crate::types::TableOptimizerType>,
    /// <p>A <code>TableOptimizerConfiguration</code> object that was specified when creating or updating a table optimizer.</p>
    pub configuration: ::std::option::Option<crate::types::TableOptimizerConfiguration>,
    /// <p>A <code>TableOptimizerRun</code> object representing the last run of the table optimizer.</p>
    pub last_run: ::std::option::Option<crate::types::TableOptimizerRun>,
}
impl TableOptimizer {
    /// <p>The type of table optimizer. The valid values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>compaction</code>: for managing compaction with a table optimizer.</p></li>
    /// <li>
    /// <p><code>retention</code>: for managing the retention of snapshot with a table optimizer.</p></li>
    /// <li>
    /// <p><code>orphan_file_deletion</code>: for managing the deletion of orphan files with a table optimizer.</p></li>
    /// </ul>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::TableOptimizerType> {
        self.r#type.as_ref()
    }
    /// <p>A <code>TableOptimizerConfiguration</code> object that was specified when creating or updating a table optimizer.</p>
    pub fn configuration(&self) -> ::std::option::Option<&crate::types::TableOptimizerConfiguration> {
        self.configuration.as_ref()
    }
    /// <p>A <code>TableOptimizerRun</code> object representing the last run of the table optimizer.</p>
    pub fn last_run(&self) -> ::std::option::Option<&crate::types::TableOptimizerRun> {
        self.last_run.as_ref()
    }
}
impl TableOptimizer {
    /// Creates a new builder-style object to manufacture [`TableOptimizer`](crate::types::TableOptimizer).
    pub fn builder() -> crate::types::builders::TableOptimizerBuilder {
        crate::types::builders::TableOptimizerBuilder::default()
    }
}

/// A builder for [`TableOptimizer`](crate::types::TableOptimizer).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TableOptimizerBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::TableOptimizerType>,
    pub(crate) configuration: ::std::option::Option<crate::types::TableOptimizerConfiguration>,
    pub(crate) last_run: ::std::option::Option<crate::types::TableOptimizerRun>,
}
impl TableOptimizerBuilder {
    /// <p>The type of table optimizer. The valid values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>compaction</code>: for managing compaction with a table optimizer.</p></li>
    /// <li>
    /// <p><code>retention</code>: for managing the retention of snapshot with a table optimizer.</p></li>
    /// <li>
    /// <p><code>orphan_file_deletion</code>: for managing the deletion of orphan files with a table optimizer.</p></li>
    /// </ul>
    pub fn r#type(mut self, input: crate::types::TableOptimizerType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of table optimizer. The valid values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>compaction</code>: for managing compaction with a table optimizer.</p></li>
    /// <li>
    /// <p><code>retention</code>: for managing the retention of snapshot with a table optimizer.</p></li>
    /// <li>
    /// <p><code>orphan_file_deletion</code>: for managing the deletion of orphan files with a table optimizer.</p></li>
    /// </ul>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::TableOptimizerType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of table optimizer. The valid values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>compaction</code>: for managing compaction with a table optimizer.</p></li>
    /// <li>
    /// <p><code>retention</code>: for managing the retention of snapshot with a table optimizer.</p></li>
    /// <li>
    /// <p><code>orphan_file_deletion</code>: for managing the deletion of orphan files with a table optimizer.</p></li>
    /// </ul>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::TableOptimizerType> {
        &self.r#type
    }
    /// <p>A <code>TableOptimizerConfiguration</code> object that was specified when creating or updating a table optimizer.</p>
    pub fn configuration(mut self, input: crate::types::TableOptimizerConfiguration) -> Self {
        self.configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A <code>TableOptimizerConfiguration</code> object that was specified when creating or updating a table optimizer.</p>
    pub fn set_configuration(mut self, input: ::std::option::Option<crate::types::TableOptimizerConfiguration>) -> Self {
        self.configuration = input;
        self
    }
    /// <p>A <code>TableOptimizerConfiguration</code> object that was specified when creating or updating a table optimizer.</p>
    pub fn get_configuration(&self) -> &::std::option::Option<crate::types::TableOptimizerConfiguration> {
        &self.configuration
    }
    /// <p>A <code>TableOptimizerRun</code> object representing the last run of the table optimizer.</p>
    pub fn last_run(mut self, input: crate::types::TableOptimizerRun) -> Self {
        self.last_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>A <code>TableOptimizerRun</code> object representing the last run of the table optimizer.</p>
    pub fn set_last_run(mut self, input: ::std::option::Option<crate::types::TableOptimizerRun>) -> Self {
        self.last_run = input;
        self
    }
    /// <p>A <code>TableOptimizerRun</code> object representing the last run of the table optimizer.</p>
    pub fn get_last_run(&self) -> &::std::option::Option<crate::types::TableOptimizerRun> {
        &self.last_run
    }
    /// Consumes the builder and constructs a [`TableOptimizer`](crate::types::TableOptimizer).
    pub fn build(self) -> crate::types::TableOptimizer {
        crate::types::TableOptimizer {
            r#type: self.r#type,
            configuration: self.configuration,
            last_run: self.last_run,
        }
    }
}
