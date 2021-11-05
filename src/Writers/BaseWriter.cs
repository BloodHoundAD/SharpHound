using System.Collections.Generic;
using System.Threading.Tasks;

namespace SharpHound.Writers
{
    public abstract class BaseWriter<T>
    {
        protected readonly string DataType;
        protected readonly List<T> Queue;
        protected int Count;
        private bool _fileCreated;
        protected bool _noOp;

        internal BaseWriter(string dataType)
        {
            DataType = dataType;
            Queue = new List<T>();
        }

        internal async Task AcceptObject(T item)
        {
            if (_noOp)
                return;
            if (!_fileCreated)
            {
                CreateFile();
                _fileCreated = true;
            }

            Queue.Add(item);
            Count++;
            if (Count % 30 == 0)
            {
                await WriteData();
                Queue.Clear();
            }
        }
        
        protected abstract Task WriteData();

        internal abstract Task FlushWriter();

        protected abstract void CreateFile();
    }
}