#![cfg(feature = "embedded-alloc")]

//! Глобальный аллокатор для встраиваемых профилей на основе `embedded-alloc`.

use embedded_alloc::Heap;

#[global_allocator]
static EMBEDDED_HEAP: Heap = Heap::empty();

/// Помощник для инициализации глобальной кучи.
pub struct EmbeddedHeap;

impl EmbeddedHeap {
    /// Инициализирует кучу `embedded-alloc`, используя статический буфер.
    ///
    /// # Safety
    ///
    /// Вызывающий код обязан передать уникальную `&'static mut` область памяти,
    /// которая не будет использоваться повторно. Обычно это `static mut BUFFER`.
    pub unsafe fn init(buffer: &'static mut [u8]) {
        let start = buffer.as_mut_ptr() as usize;
        EMBEDDED_HEAP.init(start, buffer.len());
    }

}
