#ifndef _PHY_SPACE_
#define _PHY_SPACE_

template <typename T>
struct phy_space {
        L4Re::Util::Unique_cap<L4Re::Dataspace> cap;
        L4Re::Rm::Unique_region<T> rm;
        L4Re::Dma_space::Dma_addr paddr;

        //void Mmio_data_space::alloc_ram(Size size, unsigned long alloc_flags), resource.cc
        static void dmalloc(L4Re::Util::Shared_cap<L4Re::Dma_space> dma, unsigned memsz, struct phy_space<T> *phys)
        {                   
                
                phys->cap = L4Re::chkcap(L4Re::Util::make_unique_cap<L4Re::Dataspace>(),
                                "Allocate capability for descriptors.");
                               
                auto *e = L4Re::Env::env();

                L4Re::chksys(e->mem_alloc()->alloc(memsz, phys->cap.get(),
                                                   L4Re::Mem_alloc::Continuous | L4Re::Mem_alloc::Pinned),
                             "Allocate memory.");

                //auto rm = phys->rm.get();
                //rm = 0;
                L4Re::chksys(e->rm()->attach(&phys->rm, memsz,
                        L4Re::Rm::F::Search_addr | 
                        L4Re::Rm::F::RW,
                        L4::Ipc::make_cap_rw(phys->cap.get()), 0, L4_PAGESHIFT),
                        "Attach memory to virtual memory.");

                l4_size_t ds_size = memsz;
                L4Re::chksys(dma->map(L4::Ipc::make_cap_rw(phys->cap.get()), 0, &ds_size,
                             L4Re::Dma_space::Attributes::None,
                             L4Re::Dma_space::Bidirectional,
                             &phys->paddr));    
                if (memsz > ds_size)
                        throw(L4::Out_of_memory("not really"));   
        } 
        
        static void dmfree(L4Re::Util::Shared_cap<L4Re::Dma_space> dma, unsigned memsz, struct phy_space<T> *phys) {
                auto *e = L4Re::Env::env();
                L4::Cap<L4Re::Dataspace> ds;

                L4Re::chksys(e->rm()->detach((l4_addr_t)phys->rm.get(), &ds),
                        "Attach memory to virtual memory.");

                L4Re::chksys(dma->unmap(phys->paddr, 
                        memsz, L4Re::Dma_space::Attributes::None, L4Re::Dma_space::Bidirectional));
        }

           
};

#endif /* _PHY_SPACE_ */