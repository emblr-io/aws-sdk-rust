// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The options that determine the sizing of the canvas used in a grid layout.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GridLayoutScreenCanvasSizeOptions {
    /// <p>This value determines the layout behavior when the viewport is resized.</p>
    /// <ul>
    /// <li>
    /// <p><code>FIXED</code>: A fixed width will be used when optimizing the layout. In the Amazon QuickSight console, this option is called <code>Classic</code>.</p></li>
    /// <li>
    /// <p><code>RESPONSIVE</code>: The width of the canvas will be responsive and optimized to the view port. In the Amazon QuickSight console, this option is called <code>Tiled</code>.</p></li>
    /// </ul>
    pub resize_option: crate::types::ResizeOption,
    /// <p>The width that the view port will be optimized for when the layout renders.</p>
    pub optimized_view_port_width: ::std::option::Option<::std::string::String>,
}
impl GridLayoutScreenCanvasSizeOptions {
    /// <p>This value determines the layout behavior when the viewport is resized.</p>
    /// <ul>
    /// <li>
    /// <p><code>FIXED</code>: A fixed width will be used when optimizing the layout. In the Amazon QuickSight console, this option is called <code>Classic</code>.</p></li>
    /// <li>
    /// <p><code>RESPONSIVE</code>: The width of the canvas will be responsive and optimized to the view port. In the Amazon QuickSight console, this option is called <code>Tiled</code>.</p></li>
    /// </ul>
    pub fn resize_option(&self) -> &crate::types::ResizeOption {
        &self.resize_option
    }
    /// <p>The width that the view port will be optimized for when the layout renders.</p>
    pub fn optimized_view_port_width(&self) -> ::std::option::Option<&str> {
        self.optimized_view_port_width.as_deref()
    }
}
impl GridLayoutScreenCanvasSizeOptions {
    /// Creates a new builder-style object to manufacture [`GridLayoutScreenCanvasSizeOptions`](crate::types::GridLayoutScreenCanvasSizeOptions).
    pub fn builder() -> crate::types::builders::GridLayoutScreenCanvasSizeOptionsBuilder {
        crate::types::builders::GridLayoutScreenCanvasSizeOptionsBuilder::default()
    }
}

/// A builder for [`GridLayoutScreenCanvasSizeOptions`](crate::types::GridLayoutScreenCanvasSizeOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GridLayoutScreenCanvasSizeOptionsBuilder {
    pub(crate) resize_option: ::std::option::Option<crate::types::ResizeOption>,
    pub(crate) optimized_view_port_width: ::std::option::Option<::std::string::String>,
}
impl GridLayoutScreenCanvasSizeOptionsBuilder {
    /// <p>This value determines the layout behavior when the viewport is resized.</p>
    /// <ul>
    /// <li>
    /// <p><code>FIXED</code>: A fixed width will be used when optimizing the layout. In the Amazon QuickSight console, this option is called <code>Classic</code>.</p></li>
    /// <li>
    /// <p><code>RESPONSIVE</code>: The width of the canvas will be responsive and optimized to the view port. In the Amazon QuickSight console, this option is called <code>Tiled</code>.</p></li>
    /// </ul>
    /// This field is required.
    pub fn resize_option(mut self, input: crate::types::ResizeOption) -> Self {
        self.resize_option = ::std::option::Option::Some(input);
        self
    }
    /// <p>This value determines the layout behavior when the viewport is resized.</p>
    /// <ul>
    /// <li>
    /// <p><code>FIXED</code>: A fixed width will be used when optimizing the layout. In the Amazon QuickSight console, this option is called <code>Classic</code>.</p></li>
    /// <li>
    /// <p><code>RESPONSIVE</code>: The width of the canvas will be responsive and optimized to the view port. In the Amazon QuickSight console, this option is called <code>Tiled</code>.</p></li>
    /// </ul>
    pub fn set_resize_option(mut self, input: ::std::option::Option<crate::types::ResizeOption>) -> Self {
        self.resize_option = input;
        self
    }
    /// <p>This value determines the layout behavior when the viewport is resized.</p>
    /// <ul>
    /// <li>
    /// <p><code>FIXED</code>: A fixed width will be used when optimizing the layout. In the Amazon QuickSight console, this option is called <code>Classic</code>.</p></li>
    /// <li>
    /// <p><code>RESPONSIVE</code>: The width of the canvas will be responsive and optimized to the view port. In the Amazon QuickSight console, this option is called <code>Tiled</code>.</p></li>
    /// </ul>
    pub fn get_resize_option(&self) -> &::std::option::Option<crate::types::ResizeOption> {
        &self.resize_option
    }
    /// <p>The width that the view port will be optimized for when the layout renders.</p>
    pub fn optimized_view_port_width(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.optimized_view_port_width = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The width that the view port will be optimized for when the layout renders.</p>
    pub fn set_optimized_view_port_width(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.optimized_view_port_width = input;
        self
    }
    /// <p>The width that the view port will be optimized for when the layout renders.</p>
    pub fn get_optimized_view_port_width(&self) -> &::std::option::Option<::std::string::String> {
        &self.optimized_view_port_width
    }
    /// Consumes the builder and constructs a [`GridLayoutScreenCanvasSizeOptions`](crate::types::GridLayoutScreenCanvasSizeOptions).
    /// This method will fail if any of the following fields are not set:
    /// - [`resize_option`](crate::types::builders::GridLayoutScreenCanvasSizeOptionsBuilder::resize_option)
    pub fn build(self) -> ::std::result::Result<crate::types::GridLayoutScreenCanvasSizeOptions, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::GridLayoutScreenCanvasSizeOptions {
            resize_option: self.resize_option.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resize_option",
                    "resize_option was not specified but it is required when building GridLayoutScreenCanvasSizeOptions",
                )
            })?,
            optimized_view_port_width: self.optimized_view_port_width,
        })
    }
}
